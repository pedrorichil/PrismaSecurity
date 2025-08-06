// Adicione `notify = "6.1.1"` ao seu Cargo.toml
use notify::{RecursiveMode, Watcher, Result};
use std::path::Path;
use std::process::Command; 
use std::time::Duration;

fn call_python_scanner(file_path: &str) {
    println!("[BRIDGE] Acionando scanner Python para: {}", file_path);
    
    // Constrói o comando para executar o scanner Python
    // python -m av_core.scan --file "C:\path\to\file.exe"
    let output = Command::new("python")
        .arg("-m")
        .arg("av_core.scan")
        .arg("--file")
        .arg(file_path)
        .output(); 

    match output {
        Ok(out) => {
            if out.status.success() {
                println!("[PYTHON SAYS]:\n{}", String::from_utf8_lossy(&out.stdout));
            } else {
                println!("[PYTHON ERROR]:\n{}", String::from_utf8_lossy(&out.stderr));
            }
        },
        Err(e) => {
            println!("[BRIDGE ERROR] Falha ao executar o processo Python: {}", e);
        }
    }
}

fn main() -> Result<()> {
    let mut watcher = notify::recommended_watcher(|res| {
        match res {
           Ok(event) => {
               if let notify::EventKind::Create(_) = event.kind {
                   for path in event.paths {
                       if let Some(path_str) = path.to_str() {
                           call_python_scanner(path_str);
                       }
                   }
               }
           },
           Err(e) => println!("[MONITOR] Erro de monitoramento: {:?}", e),
        }
    })?;

    let path_to_watch = "C:\\Users\\SeuUsuario\\Downloads";
    println!("[MONITOR] Monitorando o diretório: {}", path_to_watch);
    watcher.watch(Path::new(path_to_watch), RecursiveMode::Recursive)?;

    loop {
        std::thread::sleep(Duration::from_secs(60));
    }
}