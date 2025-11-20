use std::io::{self, Write};

use bloom_core::download::DownloadManager;
use bloom_core::versions::{
    VersionDescriptor, VersionManifest, VersionPaths, VersionRef, user_agent,
};
use bloom_core::{Result, config::AppPaths};
use color_eyre::eyre::{bail, eyre};
use reqwest::Client;
use tokio::fs;
use tracing::{info, warn};

#[tokio::main]
async fn main() -> Result<()> {
    color_eyre::install()?;
    bloom_core::init_tracing()?;

    let client = Client::builder()
        .user_agent(user_agent().as_ref())
        .build()?;

    info!("Fetching official Minecraft version manifest…");
    let manifest = VersionManifest::fetch(&client).await?;

    info!(
        release = %manifest.latest.release,
        snapshot = %manifest.latest.snapshot,
        total = manifest.versions.len(),
        "manifest fetched"
    );

    let candidates: Vec<&VersionRef> = manifest.versions.iter().take(10).collect();

    println!("选择需要下载的版本 (输入序号或版本ID，回车默认选择 1):");
    for (idx, version) in candidates.iter().enumerate() {
        println!(
            "{:2}. {:<20} {:<9} {}",
            idx + 1,
            version.id,
            format!("{:?}", version.kind).to_lowercase(),
            version.release_time
        );
    }

    let selected_id = prompt_for_selection(&manifest, &candidates)?;
    info!(selected = %selected_id, "user selected version");
    println!("已选择版本: {selected_id}");

    let version = manifest
        .find_version(&selected_id)
        .ok_or_else(|| eyre!("未在清单中找到版本: {selected_id}"))?;

    // Instance naming.
    let instance_name = prompt_for_instance(&selected_id)?;
    let app_paths = AppPaths::new()?;
    let instance_dir = app_paths.instances_dir.join(&instance_name);
    fs::create_dir_all(&instance_dir).await?;

    // Prepare download target and manager.
    let layout = VersionPaths::from_cache(&app_paths.cache_dir);
    let descriptor_dir = &layout.versions_dir;
    let manager = DownloadManager::new(client.clone(), 8);
    let descriptor_path = manifest
        .download_descriptor(&manager, version, descriptor_dir)
        .await?;

    let descriptor = VersionDescriptor::from_file(&descriptor_path).await?;
    let downloaded = descriptor.download_all_resources(&manager, &layout).await?;

    let launch_cmd = descriptor.build_basic_launch_command("java", &downloaded, &instance_dir);

    println!(
        "资源下载完成，版本描述文件: {}\n建议启动命令：\n{}",
        descriptor_path.display(),
        launch_cmd.join(" ")
    );

    println!("实例目录: {} (可用于保存存档/配置)", instance_dir.display());

    Ok(())
}

fn prompt_for_selection(
    manifest: &VersionManifest,
    candidates: &[&VersionRef],
) -> color_eyre::Result<String> {
    print!("你的选择: ");
    io::stdout().flush()?;

    let mut input = String::new();
    io::stdin().read_line(&mut input)?;
    let trimmed = input.trim();

    let selected_id = if trimmed.is_empty() {
        candidates
            .first()
            .map(|v| v.id.clone())
            .unwrap_or_else(|| manifest.latest.release.clone())
    } else if let Ok(idx) = trimmed.parse::<usize>() {
        if let Some(v) = candidates.get(idx.saturating_sub(1)) {
            v.id.clone()
        } else {
            warn!(choice = idx, "选择超出列表范围，使用默认项");
            candidates
                .first()
                .map(|v| v.id.clone())
                .unwrap_or_else(|| manifest.latest.release.clone())
        }
    } else {
        trimmed.to_string()
    };

    if selected_id.is_empty() {
        bail!("未选择有效的版本");
    }

    Ok(selected_id)
}

fn prompt_for_instance(default_name: &str) -> color_eyre::Result<String> {
    println!("请输入实例名称 (回车默认 {default_name}):");
    print!("实例名称: ");
    io::stdout().flush()?;

    let mut input = String::new();
    io::stdin().read_line(&mut input)?;
    let name = input.trim();
    if name.is_empty() {
        Ok(default_name.to_string())
    } else {
        Ok(name.to_string())
    }
}
