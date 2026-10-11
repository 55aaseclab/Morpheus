//! Runtime consumption of full semantic SDGs. Kernel state is never a mutation destination.
use super::*;
use alloc::{collections::{BTreeMap, BTreeSet}, sync::Arc};
use serde_json::Value as Json;
use sha2::{Digest, Sha256};
use std::io::{BufRead, BufReader};

pub type BlobRef = (u64, u64, u64, String);

fn read_blob(file: &mut std::fs::File, reference: &BlobRef) -> Result<Vec<u8>, String> {
    use std::io::{Read, Seek, SeekFrom};
    let (offset, size, raw_size, checksum) = reference;
    file.seek(SeekFrom::Start(*offset)).map_err(|e| e.to_string())?;
    let mut decoded = flate2::read::ZlibDecoder::new(file.take(*size)).take(raw_size.saturating_add(1));
    let mut bytes = Vec::new();
    decoded.read_to_end(&mut bytes).map_err(|e| e.to_string())?;
    if bytes.len() as u64 != *raw_size || format!("{:x}", Sha256::digest(&bytes)) != *checksum {
        return Err("package evidence integrity mismatch".into());
    }
    Ok(bytes)
}

/// The manifest fixes the runtime plan and evidence files. Documents are
/// reconstructed only on inspection, without expanding evidence during startup.
pub fn load_package(path: &std::path::Path) -> Result<SemanticDependencyGraph, String> {
    use std::io::Read;
    let manifest: Json = serde_json::from_slice(&std::fs::read(path.join("manifest.json")).map_err(|e|e.to_string())?)
        .map_err(|e|e.to_string())?;
    if manifest["format"] != "sdg-runtime-package" || manifest["version"] != 1 || manifest["irq_policy"] != "ignored" {
        return Err("unsupported runtime package manifest".into());
    }
    for name in ["runtime.json", "evidence.pack"] {
        let mut file=std::fs::File::open(path.join(name)).map_err(|e|e.to_string())?;
        if manifest["files"][name]["bytes"].as_u64() != Some(file.metadata().map_err(|e|e.to_string())?.len()) {
            return Err(format!("package file size mismatch: {name}"));
        }
        let mut hasher=Sha256::new();let mut buffer=[0u8;65536];
        loop { let n=file.read(&mut buffer).map_err(|e|e.to_string())?;if n==0{break}hasher.update(&buffer[..n]); }
        if manifest["files"][name]["sha256"].as_str()!=Some(format!("{:x}",hasher.finalize()).as_str()) {
            return Err(format!("package file integrity mismatch: {name}"));
        }
    }
    let runtime: Json=serde_json::from_slice(&std::fs::read(path.join("runtime.json")).map_err(|e|e.to_string())?)
        .map_err(|e|e.to_string())?;
    let plans=runtime["plans"].as_array().ok_or("package plans missing")?;
    let entries=runtime["rules"].as_array().ok_or("package rules missing")?;
    if manifest["rules"].as_u64()!=Some(entries.len() as u64) || manifest["plans"].as_u64()!=Some(plans.len() as u64) {
        return Err("package manifest counts mismatch".into());
    }
    let mut rules=Vec::new();let mut seen=BTreeSet::new();let mut compiled=BTreeMap::<usize,Rule>::new();
    for entry in entries {
        let name=string(entry,"id")?;
        if !name.starts_with("rule:") || !seen.insert(name.to_string()) {return Err("invalid or duplicate package rule".into())}
        let index=entry["plan"].as_u64().and_then(|i|usize::try_from(i).ok()).ok_or("invalid plan index")?;
        let plan=plans.get(index).ok_or("missing package plan")?;
        let recipe=entry["document"].as_u64().and_then(|v|usize::try_from(v).ok()).ok_or("invalid evidence reference")?;
        let index_ref: BlobRef=serde_json::from_value(manifest["evidence_index"].clone()).map_err(|e|e.to_string())?;
        let document=Document::Package{path:path.join("evidence.pack"),recipe,index:index_ref,sha256:string(entry,"document_sha256")?.into()};
        let mut rule=if let Some(rule)=compiled.get(&index) {rule.clone()} else {
            if plan["validation"]["result"]=="unsat" || !plan["preconditions"].is_object() {return Err("invalid package predicates".into())}
            let nodes: BTreeMap<String,Arc<Json>>=plan["nodes"].as_object().ok_or("package nodes missing")?
                .iter().map(|(k,v)|(k.clone(),Arc::new(v.clone()))).collect();
            let defs: BTreeMap<String,Arc<Json>>=plan["definitions"].as_object().ok_or("package definitions missing")?
                .iter().map(|(k,v)|(k.clone(),Arc::new(v.clone()))).collect();
            let mut fields=plan.clone();
            fields["id"]=entry["id"].clone();fields["status"]=entry["status"].clone();
            fields["path"]=serde_json::json!({"source":entry["source"]});
            let rule=build_plan(&fields,&nodes,defs,document.clone())?;
            compiled.insert(index,rule.clone());rule
        };
        rule.name=name.into();
        let sem=Arc::make_mut(rule.semantic.as_mut().ok_or("package semantic plan missing")?);
        sem.document=document;sem.status=string(entry,"status")?.into();
        rules.push(rule);
    }
    Ok(SemanticDependencyGraph{rules})
}

#[derive(Clone, Debug)]
pub struct RuntimeBlocker { pub source: String, pub reason: String }

/// The original self-contained document remains available for inspecting path,
/// assumptions and proof records. Runtime plans do not duplicate its large graph.
#[derive(Clone, Debug)]
pub enum Document {
    File { path: std::path::PathBuf, sha256: String },
    Inline(Arc<String>),
    Package { path: std::path::PathBuf, recipe: usize, index: BlobRef, sha256: String },
}
impl Document {
    pub fn read(&self) -> Result<String, String> {
        match self {
            Self::Inline(text) => Ok((**text).clone()),
            Self::Package { path, recipe, index, sha256 } => {
                let mut file = std::fs::File::open(path).map_err(|e| e.to_string())?;
                let records: Vec<BlobRef> = serde_json::from_slice(&read_blob(&mut file, index)?).map_err(|e| e.to_string())?;
                let reference = records.get(*recipe).ok_or("invalid evidence recipe")?;
                let groups: Vec<usize> = serde_json::from_slice(&read_blob(&mut file, reference)?).map_err(|e| e.to_string())?;
                let mut bytes = Vec::new();
                for group in groups {
                    let reference = records.get(group).ok_or("invalid evidence group")?;
                    let items: Vec<usize> = serde_json::from_slice(&read_blob(&mut file, reference)?).map_err(|e| e.to_string())?;
                    for item in items { bytes.extend(read_blob(&mut file, records.get(item).ok_or("invalid evidence record")?)?); }
                }
                if format!("{:x}", Sha256::digest(&bytes)) != *sha256 { return Err("package document integrity mismatch".into()); }
                String::from_utf8(bytes).map_err(|e| e.to_string())
            },
            Self::File { path, sha256 } => {
                let bytes = std::fs::read(path).map_err(|e| e.to_string())?;
                if format!("{:x}", Sha256::digest(&bytes)) != *sha256 { return Err("semantic document changed after loading".into()); }
                String::from_utf8(bytes).map_err(|e| e.to_string())
            }
        }
    }
}

#[derive(Clone, Debug)]
struct Action { source: String, operation: String, parameter: i128, side: String,
                signed: bool, min: i128, max: i128 }

#[derive(Clone, Debug)]
pub struct SemanticRule {
    pub document: Document,
    pub status: String,
    pub blockers: Vec<RuntimeBlocker>,
    pub ignored_irq_actions: usize,
    pub unavailable_sources: BTreeMap<String, String>,
    actions: Vec<Action>,
    source_specs: BTreeMap<String, Arc<Json>>,
    initial: BTreeMap<String, u64>,
    precondition: Expr,
}

#[derive(Clone, Debug)]
enum Expr { Unknown, Constant(u64, u8, bool), Source(String, u8, bool), Op(String, Vec<Arc<Expr>>, u8, bool) }
#[derive(Clone, Copy, Debug)]
struct Number { bits: u64, width: u8, signed: bool }
impl Number {
    fn truth(self) -> bool { self.bits != 0 }
    fn integer(self) -> i128 { if self.signed { signed_value(self.bits, self.width, Signedness::Signed) } else { self.bits as i128 } }
}
fn num(bits: u64, width: u8, signed: bool) -> Number { Number { bits: bits & max_for_width(width), width, signed } }
fn boolean(value: bool) -> Number { num(value as u64, 1, false) }
fn cast(value: Number, width: u8, signed: bool) -> Number { num(value.integer() as u64, width, signed) }

fn eval(expr: &Expr, values: &BTreeMap<String, Value>) -> Option<Number> {
    eval_cached(expr, values, &mut BTreeMap::new())
}

fn eval_cached(expr: &Expr, values: &BTreeMap<String, Value>, cache: &mut BTreeMap<usize, Option<Number>>) -> Option<Number> {
    let key = expr as *const Expr as usize;
    if let Some(value) = cache.get(&key) { return *value; }
    let result = (|| { match expr {
        Expr::Unknown => None,
        Expr::Constant(n,w,s) => Some(num(*n,*w,*s)),
        Expr::Source(k,w,s) => values.get(k)?.as_u64().map(|v| num(v,*w,*s)),
        Expr::Op(op, args, width, signed) => {
            let a = args.first().and_then(|e| eval_cached(e,values,cache));
            let b = args.get(1).and_then(|e| eval_cached(e,values,cache));
            match op.as_str() {
                "And" | "&&" => {
                    let mut unknown=false;
                    for e in args { match eval_cached(e,values,cache) { Some(v) if !v.truth()=>return Some(boolean(false)),None=>unknown=true,_=>{} } }
                    if unknown { None } else { Some(boolean(true)) }
                }
                "Or" | "||" => {
                    let mut unknown=false;
                    for e in args { match eval_cached(e,values,cache) { Some(v) if v.truth()=>return Some(boolean(true)),None=>unknown=true,_=>{} } }
                    if unknown { None } else { Some(boolean(false)) }
                }
                "Not" | "!" => Some(boolean(!a?.truth())),
                "Cast" | "CStyleCast" | "IntegralConversion" | "ImplicitConversion" => Some(cast(a?,*width,*signed)),
                "ParenthesisExpr" | "StmtExpr" => a,
                "=" => b,
                "Conditional" | "?" => { let c=a?; eval_cached(args.get(if c.truth(){1}else{2})?,values,cache) }
                "Eq" | "==" => Some(boolean(a?.integer()==b?.integer())),
                "Ne" | "!=" => Some(boolean(a?.integer()!=b?.integer())),
                "Lt" | "<" => Some(boolean(a?.integer()<b?.integer())),
                "Le" | "<=" => Some(boolean(a?.integer()<=b?.integer())),
                "Gt" | ">" => Some(boolean(a?.integer()>b?.integer())),
                "Ge" | ">=" => Some(boolean(a?.integer()>=b?.integer())),
                "Add" | "+" => Some(num(a?.bits.wrapping_add(b?.bits),*width,*signed)),
                "Sub" | "-" if args.len()==2 => Some(num(a?.bits.wrapping_sub(b?.bits),*width,*signed)),
                "-" => Some(num(0u64.wrapping_sub(a?.bits),*width,*signed)),
                "Mul" | "*" => Some(num(a?.bits.wrapping_mul(b?.bits),*width,*signed)),
                "&" => Some(num(a?.bits & b?.bits,*width,*signed)),
                "|" => Some(num(a?.bits | b?.bits,*width,*signed)),
                "^" => Some(num(a?.bits ^ b?.bits,*width,*signed)),
                "~" => Some(num(!a?.bits,*width,*signed)),
                "<<" if b?.bits<*width as u64 => Some(num(a?.bits << b?.bits,*width,*signed)),
                ">>" if b?.bits<*width as u64 => Some(num((a?.integer() >> b?.bits) as u64,*width,*signed)),
                "ByteSwap" => { let v=a?; Some(num(v.bits.swap_bytes()>>(64-v.width),v.width,v.signed)) }
                _ => None,
            }
        }
    } })();
    cache.insert(key, result);
    result
}

fn ty(v: &Json) -> (u8,bool) {
    let t=&v["type"];
    (t["width"].as_u64().filter(|w|*w>0 && *w<=64).unwrap_or(64) as u8,t["signedness"]=="Signed")
}
fn number(v: &Json) -> Option<i128> { v.as_i64().map(|x|x as i128).or_else(||v.as_u64().map(|x|x as i128)) }
fn string<'a>(v:&'a Json,key:&str)->Result<&'a str,String>{v[key].as_str().ok_or_else(||format!("missing {key}"))}
fn strings(v:&Json)->Result<Vec<String>,String>{ v.as_array().ok_or("expected array")?.iter().map(|x|x.as_str().map(String::from).ok_or("expected identifier".into())).collect() }
fn children(v:&Json)->Vec<&Json>{
    if v.get("left").is_some(){vec![&v["left"],&v["right"]]}
    else if v.get("operand").is_some(){vec![&v["operand"]]}
    else if v["value"].is_object(){vec![&v["value"]]}
    else { let mut a:Vec<_>=v["operands"].as_array().map(|x|x.iter().collect()).unwrap_or_default();a.sort_by_key(|e|e["position"].as_i64().unwrap_or(0));a }
}
struct Compiler<'a>{nodes:&'a BTreeMap<String,Arc<Json>>,defs:BTreeMap<String,Arc<Json>>,cache:BTreeMap<String,Arc<Expr>>,active:BTreeSet<String>}
impl Compiler<'_>{
    fn compile(&mut self,v:&Json,depth:usize)->Arc<Expr>{
        if depth>128{return Arc::new(Expr::Unknown)}
        if let Some(id)=v["node"].as_str(){
            if let Some(e)=self.cache.get(id){return e.clone()}
            let node=self.nodes.get(id);let (w,s)=node.map(|n|ty(n)).unwrap_or((64,false));
            if node.is_some_and(|n|n["kind"]=="source") {return Arc::new(Expr::Source(id.into(),w,s))}
            if !self.active.insert(id.into()){return Arc::new(Expr::Unknown)}
            let result=if let Some(def)=self.defs.get(id).cloned(){self.compile(&def,depth+1)}else{Arc::new(Expr::Unknown)};
            self.active.remove(id);self.cache.insert(id.into(),result.clone());return result
        }
        let (w,s)=ty(v);let k=v["kind"].as_str().unwrap_or("");
        if k=="Const" {return Arc::new(number(&v["value"]).map(|n|Expr::Constant(n as u64,w,s || n<0)).unwrap_or(Expr::Unknown))}
        let args=children(v).into_iter().map(|c|self.compile(c,depth+1)).collect();
        Arc::new(Expr::Op(k.into(),args,w,s))
    }
}

#[derive(Default)]
pub struct GraphPool { records: BTreeMap<[u8;32], Arc<Json>> }
impl GraphPool {
    fn json(&mut self,line:&str,payload:&str)->Result<Arc<Json>,String>{
        let hash: [u8;32]=Sha256::digest(line.as_bytes()).into();
        if let Some(value)=self.records.get(&hash){return Ok(value.clone())}
        let value: Arc<Json>=Arc::new(serde_json::from_str(payload).map_err(|e|format!("invalid graph JSON: {e}"))?);
        self.records.insert(hash,value.clone());Ok(value)
    }
}

pub fn parse(text:&str)->Result<Rule,String>{
    parse_reader(std::io::Cursor::new(text.as_bytes()),Document::Inline(Arc::new(text.into())),&mut GraphPool::default())
}
#[cfg(feature="std")]
pub fn load_file(path:&std::path::Path,pool:&mut GraphPool)->Result<Rule,String>{
    let file=std::fs::File::open(path).map_err(|e|e.to_string())?;
    let mut reader=BufReader::new(file);let mut header=String::new();reader.read_line(&mut header).map_err(|e|e.to_string())?;
    if header.trim_end_matches(['\r', '\n'])!="sdg 1.2" {return super::parse_rule(&std::fs::read_to_string(path).map_err(|e|e.to_string())?)}
    let reader=BufReader::new(std::fs::File::open(path).map_err(|e|e.to_string())?);
    parse_reader(reader,Document::File{path:path.into(),sha256:String::new()},pool)
}

fn parse_reader<R:BufRead>(mut reader:R,mut document:Document,pool:&mut GraphPool)->Result<Rule,String>{
    let mut fields=serde_json::Map::new();let mut nodes=BTreeMap::new();let mut edges=BTreeMap::new();let mut hash=Sha256::new();
    let mut buffer=String::new();let mut i=0;
    loop {
        buffer.clear();
        if reader.read_line(&mut buffer).map_err(|e|e.to_string())?==0{break}
        // Hash the stored bytes, including their original line endings.
        hash.update(buffer.as_bytes());
        let line=buffer.trim_end_matches(['\r','\n']);
        let current=i;i+=1;
        if current==0 {if line!="sdg 1.2"{return Err("expected sdg 1.2".into())}continue}
        if line.is_empty(){continue}
        let mut p=line.splitn(3,' ');let kind=p.next().unwrap_or("");
        match kind {
            "rule"=>{if fields.contains_key("id"){return Err("duplicate rule".into())}fields.insert("id".into(),Json::String(line[5..].into()));}
            "field"=>{let key=p.next().ok_or("missing field")?;let payload=p.next().ok_or("missing field data")?;
                if key=="id" || fields.contains_key(key){return Err(format!("duplicate field {key}"))}
                fields.insert(key.into(),serde_json::from_str(payload).map_err(|e|e.to_string())?);}
            "node"=>{let mut p=line.splitn(4,' ');p.next();let id=p.next().ok_or("node id")?;let k=p.next().ok_or("node kind")?;let data=p.next().ok_or("node metadata")?;
                let raw=pool.json(&line,data)?;let mut object=raw.as_object().ok_or("node object")?.clone();
                if object.contains_key("id") || object.contains_key("kind"){return Err("reserved node metadata".into())}
                object.insert("id".into(),Json::String(id.into()));object.insert("kind".into(),Json::String(k.into()));
                if nodes.insert(id.into(),Arc::new(Json::Object(object))).is_some(){return Err("duplicate node".into())}}
            "edge"=>{let mut p=line.splitn(6,' ');p.next();let id=p.next().ok_or("edge id")?;let src=p.next().ok_or("edge src")?;let dst=p.next().ok_or("edge dst")?;let head=p.next().ok_or("edge head")?;let data=p.next().ok_or("edge data")?;
                let raw=pool.json(&line,data)?;if Head::from_str(head).is_none(){return Err("unknown edge head".into())}
                if edges.insert(id.into(),(src.to_string(),dst.to_string(),head.to_string(),raw)).is_some(){return Err("duplicate edge".into())}}
            _=>return Err(format!("unknown semantic record {kind}")),
        }
    }
    if let Document::File{sha256,..}=&mut document{*sha256=format!("{:x}",hash.finalize());}
    build(Json::Object(fields),nodes,edges,document)
}

type Edges=BTreeMap<String,(String,String,String,Arc<Json>)>;
fn build(fields:Json,nodes:BTreeMap<String,Arc<Json>>,edges:Edges,document:Document)->Result<Rule,String>{
    let name=string(&fields,"id")?.to_string();if !name.starts_with("rule:"){return Err("invalid semantic rule id".into())}
    let vars=strings(&fields["vars"])?;let declared:BTreeSet<_>=vars.iter().cloned().collect();
    if declared.len()!=vars.len() || declared!=nodes.keys().cloned().collect(){return Err("node records differ from vars".into())}
    let path=&fields["path"];let source=string(path,"source")?;let sink=string(path,"sink")?;
    if nodes.get(source).is_none_or(|n|n["kind"]!="source") || nodes.get(sink).is_none_or(|n|n["kind"]!="sink"){return Err("invalid endpoints".into())}
    let ids=strings(&path["edges"])?;if ids.len()!=edges.len() || ids.iter().collect::<BTreeSet<_>>().len()!=ids.len() || ids.iter().any(|id|!edges.contains_key(id)){return Err("edge records differ from path".into())}
    for (_, (a,b,_,e)) in &edges {if !declared.contains(a)||!declared.contains(b)||e.get("predicate").is_none(){return Err("invalid edge endpoints/predicate".into())}}
    fn refs(v:&Json,declared:&BTreeSet<String>)->Result<(),String>{
        match v {Json::Object(map)=>for(k,v)in map{if matches!(k.as_str(),"node"|"src"|"dst"|"var"){if let Some(id)=v.as_str(){if !declared.contains(id){return Err(format!("undeclared reference {id}"))}}}refs(v,declared)?;},Json::Array(a)=>for v in a{refs(v,declared)?},_=>{}}Ok(())
    }
    refs(&fields,&declared)?;for (_,(_,_,_,e)) in &edges{refs(e,&declared)?}
    if fields["validation"]["result"]=="unsat"{return Err("disproved rule".into())}
    if !fields["preconditions"].is_object() || !fields["target_state"]["predicate"].is_object(){return Err("missing path/target predicates".into())}
    let mut defs=BTreeMap::new();let mut ambiguous=BTreeSet::new();
    for (_,(_,dst,head,e)) in &edges {
        let p=&e["predicate"];
        if head!="head_guard" && p["kind"]=="Eq" && p["left"]["node"]==dst.as_str() && p["right"].is_object(){
            let value=Arc::new(p["right"].clone());if let Some(old)=defs.insert(dst.clone(),value.clone()){if old!=value{ambiguous.insert(dst.clone());}}
        }
    }
    for id in ambiguous{defs.remove(&id);}
    build_plan(&fields, &nodes, defs, document)
}

fn build_plan(fields: &Json, nodes: &BTreeMap<String, Arc<Json>>,
              defs: BTreeMap<String, Arc<Json>>, document: Document) -> Result<Rule, String> {
    let name=string(fields,"id")?.to_string();
    let source=string(&fields["path"],"source")?;
    let mut compiler=Compiler{nodes,defs,cache:BTreeMap::new(),active:BTreeSet::new()};
    let precondition=(*compiler.compile(&fields["preconditions"],0)).clone();
    let mut source_specs=BTreeMap::new();let mut runtime_nodes=Vec::new();let mut unavailable=BTreeMap::new();
    let assignments=&fields["validation"]["source_assignments"];
    let mut initial=BTreeMap::new();
    for (id,n) in nodes {if n["kind"]!="source"{continue} source_specs.insert(id.clone(),n.clone());
        if n["source"]["kind"]=="Irq"{continue}
        match source_node(id,n){Ok(node)=>{if let Some(v)=assignments[id].as_u64(){if v>node.max_value(){return Err("out of width Z3 assignment".into())}initial.insert(id.clone(),v);}runtime_nodes.push(node)},Err(e)=>{unavailable.insert(id.clone(),e);}}
    }
    let hints=fields["mutation_hint"].as_array().ok_or("missing mutations")?;if hints.is_empty(){return Err("empty mutations".into())}
    let mut actions=Vec::new();let mut ignored_irq_actions=0;
    for h in hints {
        let id=string(h,"var")?;let spec=nodes.get(id).ok_or("mutation node missing")?;
        if spec["kind"]!="source"{return Err("mutation targets kernel internal state".into())}
        let op=string(h,"operator")?;
        if op=="DeliverIrq" {if spec["source"]["kind"]!="Irq"{return Err("IRQ mutation targets non-IRQ source".into())}ignored_irq_actions+=1;continue}
        let width=spec["source"]["size_bytes"].as_u64().filter(|w|*w>0&&*w<=8).ok_or("unsupported source width")? as u8*8;
        let signed=spec["type"]["signedness"]=="Signed";
        let (min,max)=if signed{(min_signed_for_width(width),max_signed_for_width(width))}else{(0,max_for_width(width)as i128)};
        let param=match op{"Inc"|"Dec"=>number(&h["delta"]),"SetBoundary"=>number(&h["boundary"]),"SetValue"=>number(&h["value"]),"SetBits"|"ClearBits"=>number(&h["mask"]),"FlipBit"=>number(&h["bit"]),"SampleRange"|"Keep"=>Some(0),_=>return Err(format!("unknown mutation {op}"))}.ok_or("invalid mutation parameter")?;
        let side=h["side"].as_str().unwrap_or("").to_string();
        if op=="SetBoundary" && !matches!(side.as_str(),"Above"|"Below"|"At"){return Err("invalid boundary side".into())}
        let action=Action{source:id.into(),operation:op.into(),parameter:param,side,signed,min:if op=="SampleRange"{number(&h["min"]).ok_or("range min")?}else{min},max:if op=="SampleRange"{number(&h["max"]).ok_or("range max")?}else{max}};
        if (matches!(op,"Inc"|"Dec"|"SetBits"|"ClearBits"|"FlipBit")&&param<0) || (op=="FlipBit"&&param>=width as i128) || (matches!(op,"SetBits"|"ClearBits")&&param>max_for_width(width)as i128) {return Err("mutation outside source domain".into())}
        if !unavailable.contains_key(id){actions.push(action)}
    }
    let mut blockers=Vec::new();
    if actions.is_empty(){blockers.push(RuntimeBlocker{source:source.into(),reason:if ignored_irq_actions==hints.len(){"IRQ actions ignored for this runtime".into()}else{"no mutation with resolved MMIO/DMA placement".into()}})}
    // Relevant source inputs with unresolved addresses must be bound by the
    // integration instead of silently assigned to an invented offset.
    for (id,reason) in &unavailable {blockers.push(RuntimeBlocker{source:id.clone(),reason:reason.clone()});}
    let placeholder=runtime_nodes.first().map(|n|n.name.clone()).unwrap_or_else(||source.into());
    let semantic=SemanticRule{document,status:fields["status"].as_str().unwrap_or("unknown").into(),blockers,ignored_irq_actions,
        unavailable_sources:unavailable,actions,source_specs,initial,precondition};
    Ok(Rule{name,nodes:runtime_nodes,preconditions:vec![],trigger:Condition{src:placeholder.clone(),dst:placeholder,head:Head::Guard,predicate:Predicate::Eq(0)},mutation:Mutation::Keep,semantic:Some(Arc::new(semantic))})
}

fn source_node(id:&str,node:&Json)->Result<Node,String>{
    let s=&node["source"];let size=s["size_bytes"].as_u64().filter(|w|*w>0&&*w<=8).ok_or("source width must be 1..8 bytes")? as u8;
    let offset=s["offset"].as_u64().and_then(|v|u32::try_from(v).ok()).ok_or("source offset requires runtime binding")?;
    let end=offset.checked_add(size as u32).ok_or("source offset overflows")?;
    let order=s["byte_order"].as_str().unwrap_or("Unknown");
    if size>1 && !matches!(order,"Little"|"Big"|"Runtime"){return Err("source byte order requires runtime binding".into())}
    if order=="Runtime" && s["access"]!="config" && size>1{return Err("runtime byte order requires binding".into())}
    if s["access_context"].as_array().is_some_and(|a|!a.is_empty()){return Err("selector/read context requires runtime binding".into())}
    let source=match s["kind"].as_str(){
        Some("MmioRead")=>{if end>crate::input::MMIO_WINDOW_BYTES{return Err("MMIO offset outside window".into())}Source::Mmio{offset,size}},
        Some("DmaReadCoherent")=>Source::Coherent{offset,size},
        Some("DmaReadStreaming")=>Source::Streaming{offset,size,slot:s["slot"].as_u64().and_then(|v|u8::try_from(v).ok()).ok_or("DMA slot requires runtime binding")?},
        _=>return Err("unsupported source surface".into())};
    Ok(Node{name:id.into(),source,width_bits:size*8})
}

fn action_value<R:Rand>(action:&Action,node:&Node,current:u64,rand:&mut R)->Result<Value,String>{
    let value=if action.signed{signed_value(current,node.width_bits,Signedness::Signed)}else{current as i128};
    let v=match action.operation.as_str(){
        "Inc"=>value.checked_add(action.parameter),"Dec"=>value.checked_sub(action.parameter),
        "SetValue"=>Some(action.parameter),"SetBoundary"=>action.parameter.checked_add(match action.side.as_str(){"Above"=>1,"Below"=>-1,_=>0}),
        "FlipBit"=>return Value::from_u64(current^(1<<action.parameter),node.width_bits),
        "SetBits"=>return Value::from_u64(current|action.parameter as u64,node.width_bits),
        "ClearBits"=>return Value::from_u64(current&!(action.parameter as u64),node.width_bits),
        "SampleRange"=>{if action.min>action.max{return Err("empty mutation range".into())}Some(action.min+uniform_below((action.max-action.min+1)as u128,rand)as i128)},
        "Keep"=>Some(value),_=>None}.ok_or("mutation overflow")?;
    let (min,max)=if action.signed{(min_signed_for_width(node.width_bits),max_signed_for_width(node.width_bits))}else{(0,node.max_value()as i128)};
    if v<min || v>max{return Err("mutation outside source domain".into())}
    Value::from_u64(encode_signed(v,node.width_bits),node.width_bits)
}

fn source_bytes(sem:&SemanticRule,node:&Node,value:&Value)->Result<Vec<u8>,String>{
    let v=value.as_u64().ok_or("non-scalar source value")?;if v>node.max_value(){return Err("source value out of width".into())}
    let size=node.size_bytes() as usize;let big=sem.source_specs[&node.name]["source"]["byte_order"]=="Big";
    Ok(if big{v.to_be_bytes()[8-size..].to_vec()}else{v.to_le_bytes()[..size].to_vec()})
}

fn place<R:Rand>(rule:&Rule,scenario:&mut SemanticScenario,rand:&mut R)->Result<(),String>{
    // Give overlapping source observations distinct visits. A model cannot
    // represent two unrelated values at the same byte and visit.
    for node in &rule.nodes {
        if scenario.placements.contains_key(&node.name){continue}
        record_placement(scenario,node,rand);
        let p=*scenario.placements.get(&node.name).ok_or("placement absent")?;
        let offset=match node.source{Source::Mmio{offset,..}|Source::Coherent{offset,..}|Source::Streaming{offset,..}=>offset};
        let mut selected=p;
        for previous in &rule.nodes {
            if previous.name==node.name{break}
            if let Some(q)=scenario.placements.get(&previous.name){
                let other=match previous.source{Source::Mmio{offset,..}|Source::Coherent{offset,..}|Source::Streaming{offset,..}=>offset};
                let same_surface=core::mem::discriminant(&previous.source)==core::mem::discriminant(&node.source);
                if same_surface && q.region==selected.region && offset<other+previous.size_bytes()as u32 && other<offset+node.size_bytes()as u32 {
                    if matches!(node.source,Source::Streaming{..}){return Err("overlapping streaming observations require one consistent binding".into())}
                    selected.visit=selected.visit.max(q.visit+1);
                }
            }
        }
        scenario.insert_placement(&node.name,selected);
    }Ok(())
}

pub fn generate<R:Rand>(rule:&Rule,rand:&mut R)->Result<SemanticScenario,String>{
    let sem=rule.semantic.as_ref().ok_or("not semantic")?;
    if !sem.blockers.is_empty(){return Err(format!("rule {} requires runtime bindings: {:?}",rule.name,sem.blockers))}
    for attempt in 0..64 {
        let mut scenario=SemanticScenario{target_rule:rule.name.clone(),..Default::default()};
        for node in &rule.nodes {scenario.insert_node(node.clone());let v=if attempt==0{sem.initial.get(&node.name).copied()}else{None};scenario.set(node.name.clone(),Value::from_u64(v.unwrap_or_else(||random_u64(rand)&node.max_value()),node.width_bits)?);}
        if attempt>0 || sem.initial.is_empty(){
            let start=rand.below(NonZeroUsize::new(sem.actions.len()).ok_or("no actions")?);
            for i in 0..sem.actions.len(){let action=&sem.actions[(start+i)%sem.actions.len()];let node=rule.node_for(&action.source).ok_or("missing mutation source")?;
                let current=scenario.values[&node.name].as_u64().ok_or("missing value")?;
                if let Ok(value)=action_value(action,node,current,rand){scenario.set(node.name.clone(),value);break}
            }
        }
        if eval(&sem.precondition,&scenario.values).is_some_and(|v|!v.truth()){continue}
        place(rule,&mut scenario,rand)?;return Ok(scenario)
    }
    Err(format!("{}: generated sources contradict evaluable path conditions",rule.name))
}

pub fn lower<R:Rand>(rule:&Rule,scenario:&mut SemanticScenario,rand:&mut R)->Result<ScenarioInput,String>{
    let sem=rule.semantic.as_ref().ok_or("not semantic")?;place(rule,scenario,rand)?;
    let mut input=ScenarioInput::default();
    for node in &rule.nodes {
        let value=scenario.values.get(&node.name).ok_or("missing source value")?;
        let bytes=source_bytes(sem,node,value)?;let p=scenario.placements[&node.name];
        match node.source {
            Source::Mmio{offset,..}=>write_bytes_at(&mut input.mmio.word_models,offset,&bytes,p.visit,rand),
            Source::Coherent{offset,..}=>{while input.dma.coherent.len()<=p.region as usize{input.dma.coherent.push(CoherentAlloc{addr:input.dma.coherent.len()as u64,word_models:vec![]})}write_bytes_at(&mut input.dma.coherent[p.region as usize].word_models,offset,&bytes,p.visit,rand)},
            Source::Streaming{offset,..}=>{if !input.dma.streaming.iter().any(|u|u.addr==p.region as u64){input.dma.streaming.push(StreamUnit{addr:p.region as u64,word_models:vec![]})}let unit=input.dma.streaming.iter_mut().find(|u|u.addr==p.region as u64).ok_or("missing streaming region")?;write_bytes_at(&mut unit.word_models,offset,&bytes,0,rand)},
        }
    }
    input.mmio.word_models.sort_by_key(|w|w.offset);input.dma.coherent.sort_by_key(|u|u.addr);input.dma.streaming.sort_by_key(|u|u.addr);
    for u in &mut input.dma.coherent{u.word_models.sort_by_key(|w|w.offset)}for u in &mut input.dma.streaming{u.word_models.sort_by_key(|w|w.offset)}
    if !input.is_valid() || crate::encoding::encoded_size(&input)>crate::input::MAX_ENCODED_SCENARIO_BYTES {
        return Err("semantic scenario exceeds wire limits".into())
    }Ok(input)
}

pub fn read_value(rule:&Rule,input:&ScenarioInput,node:&Node,p:Placement)->Option<u64>{
    let value=read_node_value(input,node,p)?;
    if rule.semantic.as_ref()?.source_specs[&node.name]["source"]["byte_order"]=="Big" {Some(value.swap_bytes()>>(64-node.width_bits))}else{Some(value)}
}

pub fn mutate<R:Rand>(rule:&Rule,rand:&mut R,input:&mut ScenarioInput,parent:&SemanticScenario)->Option<SemanticScenario>{
    let sem=rule.semantic.as_ref()?;if !sem.blockers.is_empty(){return None}
    for node in &rule.nodes{if parent.nodes.get(&node.name)!=Some(node)||read_value(rule,input,node,*parent.placements.get(&node.name)?)?!=parent.values.get(&node.name)?.as_u64()?{return None}}
    let start=rand.below(NonZeroUsize::new(sem.actions.len())?);
    for i in 0..sem.actions.len(){
        let action=&sem.actions[(start+i)%sem.actions.len()];let node=rule.node_for(&action.source)?;
        let mut child=parent.clone();let current=child.values.get(&node.name)?.as_u64()?;
        let Ok(value)=action_value(action,node,current,rand)else{continue};if value.as_u64()==Some(current){continue}
        child.set(node.name.clone(),value.clone());
        if eval(&sem.precondition,&child.values).is_some_and(|v|!v.truth()){continue}
        let bytes=source_bytes(sem,node,&value).ok()?;let p=*parent.placements.get(&node.name)?;
        let mut trial=input.clone();
        let (offset,models)=match node.source{
            Source::Mmio{offset,..}=>(offset,&mut trial.mmio.word_models),
            Source::Coherent{offset,..}=>(offset,&mut trial.dma.coherent.iter_mut().find(|u|u.addr==p.region as u64)?.word_models),
            Source::Streaming{offset,..}=>(offset,&mut trial.dma.streaming.iter_mut().find(|u|u.addr==p.region as u64)?.word_models)};
        let mut success=true;for (i,byte) in bytes.iter().enumerate(){if update_byte_in_models_at(models,offset+i as u32,*byte,p.visit).is_err(){success=false;break}}
        if !success || !trial.is_valid() || crate::encoding::encoded_size(&trial)>crate::input::MAX_ENCODED_SCENARIO_BYTES || encode_scenarios_equal(&trial,input){continue}
        *input=trial;return Some(child)
    }None
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use libafl_bolts::rands::StdRand;

    fn fixture(kind:&str, size:u8, offset:Option<u32>, op:Json, condition:Json) -> String {
        let source=json!({"source":{"kind":kind,"size_bytes":size,"offset":offset,"slot":0,"byte_order":"Little"},
            "type":{"width":size*8,"signedness":"Unsigned"}});
        let fields=json!({"status":"conditional","vars":["input","sink"],
            "path":{"source":"input","sink":"sink","edges":["edge"]},
            "preconditions":condition,"target_state":{"src":"input","dst":"input","head":"head_bound",
                "predicate":{"kind":"Eq","left":{"node":"input"},"right":{"kind":"Const","value":123}}},
            "mutation_hint":[op],"assumptions":[{"kind":"kernel_path_condition","status":"assumed"}],
            "validation":{"result":"unknown"}});
        let mut text="sdg 1.2\nrule rule:fixture\n".to_string();
        for(k,v)in fields.as_object().unwrap(){text+=&format!("field {k} {v}\n")}
        text+=&format!("node input source {source}\nnode sink sink {{\"operation\":\"copy\"}}\n");
        text+="edge edge input sink head_call {\"predicate\":{\"kind\":\"Identity\",\"node\":\"input\"}}\n";text
    }
    fn increment()->Json {json!({"operator":"Inc","var":"input","delta":1})}
    fn unconstrained()->Json{json!({"kind":"And","operands":[]})}

    #[test]
    fn full_format_generates_and_mutates_conditional_rule() {
        let rule=parse(&fixture("MmioRead",1,Some(4),increment(),unconstrained())).unwrap();
        let graph=SemanticDependencyGraph{rules:vec![rule.clone()]};let mut rand=StdRand::with_seed(7);
        let mut scenario=graph.generate(&mut rand).unwrap();scenario.set("input".into(),Value::U8(40));
        let mut input=lower_scenario(&mut scenario,&rule,&mut rand).unwrap();
        let child=graph.mutate_scenario(&mut rand,&mut input,&scenario).unwrap();
        assert_eq!(child.values["input"].as_u64(),Some(41));
        assert_eq!(lift_with(&input,&rule,&child.placements).unwrap().values,child.values);
        assert_eq!(rule.semantic.as_ref().unwrap().status,"conditional");
        assert!(rule.semantic.as_ref().unwrap().document.read().unwrap().contains("kernel_path_condition"));
    }
    #[test]
    fn known_false_precondition_skips_mutation_atomically() {
        let rule=parse(&fixture("MmioRead",1,Some(4),increment(),json!({"kind":"Le","left":{"node":"input"},"right":{"kind":"Const","value":40}}))).unwrap();
        let graph=SemanticDependencyGraph{rules:vec![rule.clone()]};let mut rand=StdRand::with_seed(3);
        let mut scenario=SemanticScenario{target_rule:rule.name.clone(),..Default::default()};scenario.insert_node(rule.nodes[0].clone());scenario.set("input".into(),Value::U8(40));
        let mut input=lower_scenario(&mut scenario,&rule,&mut rand).unwrap();let original=input.clone();
        assert!(graph.mutate_scenario(&mut rand,&mut input,&scenario).is_none());assert_eq!(input,original);
    }
    #[test]
    fn unsigned_overflow_does_not_wrap() {
        let rule=parse(&fixture("MmioRead",1,Some(4),increment(),unconstrained())).unwrap();
        let action=&rule.semantic.as_ref().unwrap().actions[0];
        assert!(action_value(action,&rule.nodes[0],255,&mut StdRand::with_seed(1)).is_err());
    }

    #[test]
    fn shared_expression_is_evaluated_once_per_scenario() {
        let mut expression = Arc::new(Expr::Source("input".into(), 32, false));
        for _ in 0..48 {
            expression = Arc::new(Expr::Op("Add".into(), vec![expression.clone(), expression], 32, false));
        }
        let values = BTreeMap::from([("input".into(), Value::U32(1))]);
        let mut cache = BTreeMap::new();
        assert_eq!(eval_cached(&expression, &values, &mut cache).unwrap().bits, 0);
        assert_eq!(cache.len(), 49);
    }
    #[test]
    fn source_boundary_at_is_executable_without_exact_target_proof() {
        let rule=parse(&fixture("MmioRead",4,Some(4),json!({"operator":"SetBoundary","var":"input","boundary":2,"side":"At"}),unconstrained())).unwrap();
        let graph=SemanticDependencyGraph{rules:vec![rule.clone()]};let mut rand=StdRand::with_seed(9);
        let mut scenario=graph.generate(&mut rand).unwrap();assert_eq!(scenario.values["input"].as_u64(),Some(2));
        let input=lower_scenario(&mut scenario,&rule,&mut rand).unwrap();assert_eq!(read_value(&rule,&input,&rule.nodes[0],scenario.placements["input"]),Some(2));
    }
    #[test]
    fn big_endian_roundtrip_and_mutation_preserve_placement() {
        let text=fixture("MmioRead",2,Some(5),increment(),unconstrained()).replace("\"Little\"","\"Big\"");
        let rule=parse(&text).unwrap();let graph=SemanticDependencyGraph{rules:vec![rule.clone()]};let mut rand=StdRand::with_seed(8);
        let mut scenario=graph.generate(&mut rand).unwrap();scenario.set("input".into(),Value::U16(0x1234));
        let mut input=lower_scenario(&mut scenario,&rule,&mut rand).unwrap();
        assert_eq!(read_node_value(&input,&rule.nodes[0],scenario.placements["input"]),Some(0x3412));
        assert_eq!(lift_with(&input,&rule,&scenario.placements).unwrap().values,scenario.values);
        let child=graph.mutate_scenario(&mut rand,&mut input,&scenario).unwrap();assert_eq!(child.values["input"].as_u64(),Some(0x1235));
        assert_eq!(child.placements,scenario.placements);
    }
    #[test]
    fn dma_sources_use_existing_wire_surfaces() {
        for kind in ["DmaReadCoherent","DmaReadStreaming"] {
            let rule=parse(&fixture(kind,4,Some(8),increment(),unconstrained())).unwrap();
            let graph=SemanticDependencyGraph{rules:vec![rule.clone()]};let mut rand=StdRand::with_seed(1);
            let mut scenario=graph.generate(&mut rand).unwrap();let mut input=lower_scenario(&mut scenario,&rule,&mut rand).unwrap();
            assert_eq!(lift_with(&input,&rule,&scenario.placements).unwrap().values,scenario.values);
            let child=graph.mutate_scenario(&mut rand,&mut input,&scenario).unwrap();assert_eq!(lift_with(&input,&rule,&child.placements).unwrap().values,child.values);
        }
    }
    #[test]
    fn dynamic_offset_is_reported_without_inventing_an_address() {
        let rule=parse(&fixture("DmaReadStreaming",4,None,increment(),unconstrained())).unwrap();
        assert!(!rule.runtime_blockers().is_empty());assert!(rule.nodes.is_empty());
    }
    #[test]
    fn irq_is_ignored_and_does_not_create_fake_mmio() {
        let text=fixture("Irq",1,None,json!({"operator":"DeliverIrq","var":"input","handler":"handler"}),unconstrained());
        let rule=parse(&text).unwrap();assert_eq!(rule.semantic.as_ref().unwrap().ignored_irq_actions,1);assert!(rule.nodes.is_empty());
        assert!(!rule.runtime_blockers().is_empty());
    }
    #[test]
    fn dangling_edges_duplicate_fields_and_internal_mutations_are_rejected() {
        let text=fixture("MmioRead",1,Some(4),increment(),unconstrained());
        assert!(parse(&text.replace("edge edge input sink","edge edge absent sink")).is_err());
        assert!(parse(&(text.clone()+"field status \"conditional\"\n")).is_err());
        assert!(parse(&text.replace("node input source","node input internal")).is_err());
    }

    #[test]
    fn package_rejects_missing_or_modified_files() {
        let directory = std::env::temp_dir().join(format!(
            "semantic-package-{}-{:?}", std::process::id(), std::time::SystemTime::now()
        ));
        std::fs::create_dir_all(&directory).unwrap();
        let runtime = br#"{"plans":[],"rules":[]}"#;
        let evidence = b"evidence";
        let manifest = json!({"format":"sdg-runtime-package","version":1,
            "irq_policy":"ignored","rules":0,"plans":0,"files":{
                "runtime.json":{"bytes":runtime.len(),"sha256":format!("{:x}",Sha256::digest(runtime))},
                "evidence.pack":{"bytes":evidence.len(),"sha256":format!("{:x}",Sha256::digest(evidence))}}});
        std::fs::write(directory.join("manifest.json"),manifest.to_string()).unwrap();
        std::fs::write(directory.join("runtime.json"),runtime).unwrap();
        std::fs::write(directory.join("evidence.pack"),evidence).unwrap();
        assert!(load_package(&directory).unwrap().rules.is_empty());
        std::fs::write(directory.join("evidence.pack"),b"Evidence").unwrap();
        assert!(load_package(&directory).unwrap_err().contains("integrity mismatch"));
        std::fs::remove_file(directory.join("runtime.json")).unwrap();
        assert!(SemanticDependencyGraph::from_dir(&directory).is_err());
        std::fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn file_document_hash_uses_exact_bytes_and_detects_changes() {
        let directory = std::env::temp_dir().join(format!(
            "semantic-document-{}-{:?}", std::process::id(), std::time::SystemTime::now()
        ));
        std::fs::create_dir_all(&directory).unwrap();
        let path = directory.join("rule.sdg");
        let original = fixture("MmioRead", 1, Some(4), increment(), unconstrained());
        for text in [original.clone(), original.trim_end().to_string(), original.replace('\n', "\r\n")] {
            std::fs::write(&path, &text).unwrap();
            let rule = load_file(&path, &mut GraphPool::default()).unwrap();
            let document = &rule.semantic.as_ref().unwrap().document;
            assert_eq!(document.read().unwrap(), text);
            std::fs::write(&path, format!("{text}\n")).unwrap();
            assert!(document.read().is_err());
        }
        std::fs::remove_dir_all(directory).unwrap();
    }

    struct TestState { rand: StdRand }
    impl libafl::state::HasRand for TestState {
        type Rand = StdRand;
        fn rand(&self) -> &StdRand { &self.rand }
        fn rand_mut(&mut self) -> &mut StdRand { &mut self.rand }
    }

    #[test]
    fn semantic_generator_and_mutator_share_exact_wire_metadata() {
        use libafl::{generators::Generator, mutators::{MutationResult, Mutator}};
        use crate::{generator::ScenarioGenerator, mutator::ScenarioMutator};
        let rule = parse(&fixture("MmioRead", 4, Some(4), increment(), unconstrained())).unwrap();
        let mut generator = ScenarioGenerator::with_sdg(SemanticDependencyGraph { rules: vec![rule.clone()] });
        let mut state = TestState { rand: StdRand::with_seed(7) };
        let input = generator.generate(&mut state).unwrap();
        let parent = generator.metadata().lookup(&input).unwrap();
        assert_eq!(parent.target_rule, rule.name);
        let bytes = crate::encoding::encode_scenario(&input);
        assert_eq!(crate::encoding::decode_scenario(&bytes).unwrap(), input);
        let mut mutator = ScenarioMutator::new(generator.clone());
        let mut checked = false;
        for seed in 0..32 {
            state.rand = StdRand::with_seed(seed);
            let mut candidate = input.clone();
            if mutator.mutate(&mut state, &mut candidate).unwrap() != MutationResult::Mutated { continue }
            // Random wire mutations have no semantic record for their new bytes.
            let Some(child) = generator.metadata().lookup(&candidate) else { continue };
            assert_eq!(child.placements, parent.placements);
            assert_eq!(child.values["input"].as_u64(), parent.values["input"].as_u64().map(|v| v + 1));
            assert_eq!(lift_with(&candidate, &rule, &child.placements).unwrap().values, child.values);
            let bytes = crate::encoding::encode_scenario(&candidate);
            assert_eq!(crate::encoding::decode_scenario(&bytes).unwrap(), candidate);
            checked = true;
            break;
        }
        assert!(checked, "semantic mutation should register a child record");
    }

    #[test]
    fn unresolved_and_irq_only_rules_use_random_fallback() {
        use libafl::{generators::Generator, mutators::Mutator};
        use crate::{generator::ScenarioGenerator, mutator::ScenarioMutator};
        for text in [
            fixture("DmaReadStreaming", 4, None, increment(), unconstrained()),
            fixture("Irq", 1, None, json!({"operator":"DeliverIrq","var":"input"}), unconstrained()),
        ] {
            let graph = SemanticDependencyGraph { rules: vec![parse(&text).unwrap()] };
            assert!(!graph.has_executable_rules());
            let mut generator = ScenarioGenerator::with_sdg(graph);
            let mut fallback = ScenarioGenerator::default();
            let mut actual_state = TestState { rand: StdRand::with_seed(9) };
            let mut expected_state = TestState { rand: StdRand::with_seed(9) };
            let mut actual = generator.generate(&mut actual_state).unwrap();
            let mut expected = fallback.generate(&mut expected_state).unwrap();
            assert_eq!(actual, expected);
            assert!(actual.is_valid());
            assert!(generator.metadata().lookup(&actual).is_none());
            let actual_result = ScenarioMutator::new(generator).mutate(&mut actual_state, &mut actual).unwrap();
            let expected_result = ScenarioMutator::new(fallback).mutate(&mut expected_state, &mut expected).unwrap();
            assert_eq!(actual_result, expected_result);
            assert_eq!(actual, expected);
            assert!(actual.is_valid());
        }
    }
}
