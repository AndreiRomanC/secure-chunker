use aes_gcm::{aead::{Aead, KeyInit}, Aes256Gcm, Nonce};
use anyhow::{bail, Context, Result};
use argon2::Argon2;
use eframe::egui;
use rand::{rngs::OsRng, RngCore};
use serde::{Deserialize, Serialize};
use std::{fs::{self, File}, io::{Read, Write}, path::{Path, PathBuf}};

const MAGIC: &[u8; 8] = b"SCPACK01";

#[derive(Serialize, Deserialize)]
struct Manifest { version:u32, salt:String, chunks:Vec<ChunkMeta> }
#[derive(Serialize, Deserialize)]
struct ChunkMeta { file:String, nonce:String, size:usize }

fn derive_key(password:&str, salt:&[u8]) -> Result<[u8;32]> {
    let mut key=[0u8;32];
    Argon2::default().hash_password_into(password.as_bytes(), salt, &mut key)
        .map_err(|e| anyhow::anyhow!("key derivation failed: {e}"))?;
    Ok(key)
}

fn pack_folder(input:&Path, output:&Path, password:&str, chunk_mb:usize) -> Result<()> {
    if password.len() < 8 { bail!("Use a password of at least 8 characters"); }
    fs::create_dir_all(output)?;
    let tar_path=output.join(".working.tar.zst");
    {
        let f=File::create(&tar_path)?;
        let enc=zstd::Encoder::new(f, 6)?;
        let mut tar=tar::Builder::new(enc);
        tar.append_dir_all("data", input)?;
        let enc=tar.into_inner()?;
        enc.finish()?;
    }
    let mut salt=[0u8;16]; OsRng.fill_bytes(&mut salt);
    let key=derive_key(password,&salt)?;
    let cipher=Aes256Gcm::new_from_slice(&key).unwrap();
    let mut src=File::open(&tar_path)?;
    let chunk_size=chunk_mb.max(1)*1024*1024;
    let mut chunks=Vec::new(); let mut idx=0usize;
    loop {
        let mut buf=vec![0u8;chunk_size]; let n=src.read(&mut buf)?;
        if n==0 { break; } buf.truncate(n);
        let mut nonce=[0u8;12]; OsRng.fill_bytes(&mut nonce);
        let ct=cipher.encrypt(Nonce::from_slice(&nonce), buf.as_ref())
            .map_err(|_| anyhow::anyhow!("encryption failed"))?;
        let name=format!("part_{idx:06}.bin");
        let mut out=File::create(output.join(&name))?;
        out.write_all(MAGIC)?; out.write_all(&ct)?;
        chunks.push(ChunkMeta{file:name,nonce:hex::encode(nonce),size:n}); idx+=1;
    }
    fs::remove_file(&tar_path).ok();
    let m=Manifest{version:1,salt:hex::encode(salt),chunks};
    fs::write(output.join("manifest.json"), serde_json::to_vec_pretty(&m)?)?;
    Ok(())
}

fn unpack_folder(input:&Path, output:&Path, password:&str) -> Result<()> {
    fs::create_dir_all(output)?;
    let m:Manifest=serde_json::from_slice(&fs::read(input.join("manifest.json"))?)?;
    let salt=hex::decode(m.salt)?; let key=derive_key(password,&salt)?;
    let cipher=Aes256Gcm::new_from_slice(&key).unwrap();
    let temp=output.join(".working.tar.zst"); let mut dst=File::create(&temp)?;
    for c in m.chunks {
        let bytes=fs::read(input.join(&c.file)).with_context(|| format!("missing {}",c.file))?;
        if bytes.len()<MAGIC.len() || &bytes[..MAGIC.len()]!=MAGIC { bail!("invalid chunk {}",c.file); }
        let nonce=hex::decode(c.nonce)?;
        let pt=cipher.decrypt(Nonce::from_slice(&nonce), &bytes[MAGIC.len()..])
            .map_err(|_| anyhow::anyhow!("authentication failed: wrong password or damaged data"))?;
        dst.write_all(&pt)?;
    }
    drop(dst);
    let f=File::open(&temp)?; let dec=zstd::Decoder::new(f)?; let mut ar=tar::Archive::new(dec);
    ar.unpack(output)?; fs::remove_file(temp).ok(); Ok(())
}

#[derive(Default)]
struct App { source:String, destination:String, password:String, chunk_mb:String, status:String, mode:bool }
impl eframe::App for App {
 fn update(&mut self, ctx:&egui::Context, _:&mut eframe::Frame) {
  egui::CentralPanel::default().show(ctx, |ui| {
   ui.heading("Secure Chunker");
   ui.horizontal(|ui| { ui.selectable_value(&mut self.mode,false,"Pack"); ui.selectable_value(&mut self.mode,true,"Unpack"); });
   ui.label("Source folder"); ui.horizontal(|ui| { ui.text_edit_singleline(&mut self.source); if ui.button("Browse").clicked(){ if let Some(p)=rfd::FileDialog::new().pick_folder(){self.source=p.display().to_string();}} });
   ui.label("Destination folder"); ui.horizontal(|ui| { ui.text_edit_singleline(&mut self.destination); if ui.button("Browse").clicked(){ if let Some(p)=rfd::FileDialog::new().pick_folder(){self.destination=p.display().to_string();}} });
   ui.label("Password"); ui.add(egui::TextEdit::singleline(&mut self.password).password(true));
   if !self.mode { ui.label("Chunk size (MiB)"); if self.chunk_mb.is_empty(){self.chunk_mb="16".into();} ui.text_edit_singleline(&mut self.chunk_mb); }
   if ui.button(if self.mode{"Unpack"}else{"Pack"}).clicked(){
    let s=PathBuf::from(&self.source); let d=PathBuf::from(&self.destination);
    let r=if self.mode {unpack_folder(&s,&d,&self.password)} else {pack_folder(&s,&d,&self.password,self.chunk_mb.parse().unwrap_or(16))};
    self.status=match r {Ok(_)=>"Done.".into(),Err(e)=>format!("Error: {e:#}")};
   }
   ui.separator(); ui.label(&self.status);
  });
 }
}
fn main()->eframe::Result<()> { eframe::run_native("Secure Chunker", eframe::NativeOptions::default(), Box::new(|_| Ok(Box::<App>::default()))) }
