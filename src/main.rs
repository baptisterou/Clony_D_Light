use std::fs::OpenOptions;
use std::io::{self, Read, Write};
use std::path::PathBuf;
use std::sync::{atomic::{AtomicBool, Ordering}, Arc};
use anyhow::{anyhow, Context, Result};
use clap::{ArgGroup, Parser};
use indicatif::{ProgressBar, ProgressStyle};

#[derive(Parser, Debug)]
#[command(name = "clonit", version, about = "Clonage bit-à-bit rapide (CLI)")]
#[command(group(
    ArgGroup::new("ops")
        .multiple(true)
        .args(["verify", "no_progress"])
))]
struct Cli {
    /// Source (fichier image, volume ou disque, ex: \\.\PhysicalDrive1)
    #[arg(short = 's', long = "src")]
    src: PathBuf,

    /// Destination (fichier, volume ou disque, ex: \\.\PhysicalDrive2)
    #[arg(short = 'd', long = "dst")]
    dst: PathBuf,

    /// Taille du bloc de lecture/écriture (octets). Ex: 4M, 1M, 512K, 65536
    #[arg(long = "block-size", default_value = "4M")]
    block_size: String,

    /// Taille à cloner (octets). Si non fournie, tentera de déduire depuis la source.
    #[arg(long = "size")]
    size: Option<String>,

    /// Décalage initial à ignorer sur la source (octets).
    #[arg(long = "skip")]
    skip: Option<String>,

    /// Vérifie en relisant et comparant la destination après écriture (plus lent).
    #[arg(long = "verify")]
    verify: bool,

    /// Désactive la barre de progression.
    #[arg(long = "no-progress")]
    no_progress: bool,

    /// Confirme la destruction potentielle des données sur la destination.
    #[arg(long = "yes")] 
    yes: bool,
}

fn human_to_bytes(s: &str) -> Result<u64> {
    // Supporte suffixes: K, M, G, T (base 1024). Sans suffixe = octets.
    let s = s.trim();
    if s.is_empty() { return Err(anyhow!("valeur vide")); }
    let (num, mul) = match s.chars().last().unwrap() {
        'K' | 'k' => (&s[..s.len()-1], 1024u64),
        'M' | 'm' => (&s[..s.len()-1], 1024u64.pow(2)),
        'G' | 'g' => (&s[..s.len()-1], 1024u64.pow(3)),
        'T' | 't' => (&s[..s.len()-1], 1024u64.pow(4)),
        _ => (s, 1u64),
    };
    let v: u64 = num.replace('_', "").parse()
        .with_context(|| format!("impossible de parser la taille '{s}'"))?;
    Ok(v.saturating_mul(mul))
}

fn detect_dangerous_path(p: &PathBuf) -> bool {
    // Heuristique simple: si le chemin contient "\\.\PhysicalDrive" ou "\\.\" en tête
    // on considère que c'est un périphérique brut.
    if let Some(s) = p.to_str() { s.starts_with(r"\\.\") } else { false }
}

fn open_src(path: &PathBuf, skip: u64) -> Result<(std::fs::File, Option<u64>)> {
    let mut f = OpenOptions::new()
        .read(true)
        .open(path)
        .with_context(|| format!("ouverture source: {}", path.display()))?;

    if skip > 0 {
        io::Seek::seek(&mut f, io::SeekFrom::Start(skip))
            .with_context(|| format!("seek source à {}", skip))?;
    }
    // Essayons d'obtenir la taille si disponible (fichiers). Pour les disques bruts, peut échouer.
    let size = match f.metadata() {
        Ok(m) => Some(m.len().saturating_sub(skip)),
        Err(_) => None,
    };
    Ok((f, size))
}

fn open_dst(path: &PathBuf) -> Result<std::fs::File> {
    let f = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .open(path)
        .with_context(|| format!("ouverture destination: {}", path.display()))?;
    Ok(f)
}

fn main() -> Result<()> {
    let args = Cli::parse();

    if !args.yes && detect_dangerous_path(&args.dst) {
        return Err(anyhow!(
            "Destination semble être un périphérique brut. Ajoutez --yes pour confirmer la destruction des données."
        ));
    }

    let block_size = human_to_bytes(&args.block_size)?;
    if block_size == 0 { return Err(anyhow!("block-size ne peut pas être 0")); }

    let skip = match args.skip { Some(s) => human_to_bytes(&s)?, None => 0 };
    let (mut src, auto_size) = open_src(&args.src, skip)?;
    let mut dst = open_dst(&args.dst)?;

    let total = match (args.size.as_ref().map(|s| human_to_bytes(s)), auto_size) {
        (Some(Ok(v)), _) => v,
        (None, Some(v)) => v,
        (Some(Err(e)), _) => return Err(e),
        (None, None) => {
            return Err(anyhow!(
                "Impossible de déterminer la taille à cloner. Spécifiez --size (ex: --size 256G)."
            ))
        }
    };

    // Ctrl-C pour interrompre proprement
    let interrupted = Arc::new(AtomicBool::new(false));
    {
        let interrupted = interrupted.clone();
        ctrlc::set_handler(move || {
            interrupted.store(true, Ordering::SeqCst);
        }).expect("impossible d'enregistrer le handler Ctrl-C");
    }

    let pb = if args.no_progress { None } else {
        let pb = ProgressBar::new(total);
        pb.set_style(ProgressStyle::with_template(
            "{spinner:.green} [{elapsed_precise}] {bar:40.cyan/blue} {bytes}/{total_bytes} ({bytes_per_sec}, {eta})"
        ).unwrap());
        Some(pb)
    };

    let mut buf = vec![0u8; block_size as usize];
    let mut written: u64 = 0;

    while written < total {
        if interrupted.load(Ordering::SeqCst) {
            eprintln!("Interrompu par l'utilisateur. {written} octets écrits.");
            break;
        }

        let remaining = (total - written) as usize;
        let to_read = remaining.min(buf.len());
        let chunk = &mut buf[..to_read];

        let n = match src.read(chunk) {
            Ok(0) => break, // EOF prématurée
            Ok(n) => n,
            Err(e) => return Err(anyhow!("erreur lecture: {e}")),
        };

        dst.write_all(&chunk[..n]).with_context(|| "erreur écriture")?;

        if args.verify {
            // Relire à partir de la destination pour vérifier
            use io::Seek;
            let pos = written;
            let mut vbuf = vec![0u8; n];
            io::Seek::seek(&mut dst, io::SeekFrom::Start(pos))?;
            dst.read_exact(&mut vbuf)?;
            if vbuf[..] != chunk[..n] {
                return Err(anyhow!(
                    "vérification échouée à l'offset {} ({} octets)", pos, n
                ));
            }
            // Replacer curseur destination en fin pour continuer à écrire
            io::Seek::seek(&mut dst, io::SeekFrom::Start(pos + n as u64))?;
        }

        written += n as u64;
        if let Some(pb) = &pb { pb.set_position(written); }
    }

    if let Some(pb) = &pb { pb.finish_with_message("Terminé"); }

    // Forcer flush sur disque
    dst.flush()?;

    println!("Clonage terminé: {} octets écrits", written);
    Ok(())
}
