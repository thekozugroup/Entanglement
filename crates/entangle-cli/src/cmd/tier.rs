use std::io::{self, IsTerminal, Write};

use anyhow::{bail, ensure, Context};
use clap::{Args, Subcommand};
use entangle_rpc::{Client, TierPolicyAction, TierPolicyParams};

#[derive(Args, Debug)]
pub struct ConfigArgs {
    #[command(subcommand)]
    command: ConfigCommand,
}

#[derive(Subcommand, Debug)]
enum ConfigCommand {
    /// Check the proposed ceiling against the running daemon's plugins.
    Validate,
    /// Reload the security ceiling from config.toml.
    Reload,
}

#[derive(Args, Debug)]
pub struct SecurityArgs {
    #[command(subcommand)]
    command: SecurityCommand,
}

#[derive(Subcommand, Debug)]
enum SecurityCommand {
    /// Apply a new tier ceiling to the running daemon and its configuration.
    SetMaxTier {
        #[arg(value_parser = clap::value_parser!(u8).range(1..=5))]
        tier: u8,
        /// Drain and disable all affected plugins without an interactive prompt.
        #[arg(long)]
        force_unload: bool,
    },
}

pub async fn config(args: ConfigArgs) -> anyhow::Result<()> {
    execute(None, false, matches!(args.command, ConfigCommand::Validate)).await
}

pub async fn security(args: SecurityArgs) -> anyhow::Result<()> {
    let SecurityCommand::SetMaxTier { tier, force_unload } = args.command;
    execute(Some(tier), force_unload, false).await
}

async fn execute(target: Option<u8>, force: bool, validate: bool) -> anyhow::Result<()> {
    let client = Client::new(Client::default_socket());
    let review = client
        .tier_policy(TierPolicyParams {
            target,
            action: TierPolicyAction::Review,
            approved: None,
        })
        .await?;
    if !review.affected.is_empty() {
        let list = review
            .affected
            .iter()
            .map(|(id, tier)| format!("  {id} (tier {tier})"))
            .collect::<Vec<_>>()
            .join("\n");
        let message = format!(
            "Lowering max_tier_allowed from {} to {} affects {} loaded plugins:\n{list}",
            review.current,
            review.proposed,
            review.affected.len()
        );
        if force {
            eprintln!("{message}");
        } else {
            println!("{message}");
        }
        ensure!(
            !validate,
            "the proposed ceiling requires an operator decision"
        );
    }
    if validate {
        println!(
            "Configuration valid for the running plugins (tier ceiling {}).",
            review.proposed
        );
        return Ok(());
    }
    let mut action = TierPolicyAction::Apply;
    if !review.affected.is_empty() && !force {
        ensure!(
            io::stdin().is_terminal(),
            "interactive approval required; use entangle security set-max-tier {} --force-unload",
            review.proposed
        );
        print!(
            "Decision [u] unload-and-disable (default), [c] cancel and restore tier {}: ",
            review.current
        );
        io::stdout().flush()?;
        let mut line = String::new();
        ensure!(
            io::stdin()
                .read_line(&mut line)
                .context("reading tier decision")?
                > 0,
            "no decision received"
        );
        action = match line.trim().to_ascii_lowercase().as_str() {
            "" | "u" => TierPolicyAction::Apply,
            "c" => TierPolicyAction::Cancel,
            _ => bail!("expected u or c; no changes applied"),
        };
    }
    let result = client
        .tier_policy(TierPolicyParams {
            target,
            action,
            approved: Some(review),
        })
        .await?;
    if action == TierPolicyAction::Cancel {
        println!(
            "Cancelled. Restored max_tier_allowed to {}.",
            result.current
        );
    } else {
        println!("Applied max_tier_allowed = {}.", result.proposed);
    }
    Ok(())
}
