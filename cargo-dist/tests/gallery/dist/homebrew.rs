use std::{path::PathBuf, process::Output};

use camino::Utf8PathBuf;

use super::*;

impl AppResult {
    // Runs the installer script in the system's Homebrew installation
    #[allow(unused_variables)]
    pub fn runtest_homebrew_installer(&self, ctx: &TestContext<Tools>) -> Result<()> {
        // Only do this if we trust hashes (outside cfg so the compiler knows we use this)
        if !self.trust_hashes {
            return Ok(());
        }

        // Only do this on macOS, and only do it if RUIN_MY_COMPUTER_WITH_INSTALLERS is set
        if std::env::var(ENV_RUIN_ME)
            .map(|s| s == "homebrew" || s == "all")
            .unwrap_or(false)
        {
            // only do this if the formula exists
            let Some(formula_path) = &self.homebrew_installer_path else {
                return Ok(());
            };

            // don't do this if the test asked not to do it,
            // cf. https://github.com/axodotdev/cargo-dist/issues/1525
            if self.homebrew_skip_install {
                return Ok(());
            }

            // Only do this if Homebrew is installed
            let Some(homebrew) = &ctx.tools.homebrew else {
                return Ok(());
            };

            let mut tap_directory = brew_repo_path(homebrew).unwrap();
            tap_directory.push("Library");
            tap_directory.push("Taps");
            tap_directory.push("cargo-dist-tests");
            std::fs::create_dir_all(&tap_directory).map_err(|e| {
                miette!("failed to create tap parent directory '{tap_directory}': {e}")
            })?;

            // With https://github.com/Homebrew/brew/issues/18371
            // Homebrew now refuses to install formula that are not
            // present in a tap. We need to place the test formula
            // within the `Taps` directory of the Homebrew repository
            // for it to be installed.
            // (We could also skip individual lints via
            // --except-cop on the `brew style` CLI, but that's
            // a bit too much of a game of whack a mole.)
            let temp_root = tempfile::Builder::new()
                .prefix("homebrew-")
                .tempdir_in(&tap_directory)
                .map_err(|e| miette!("failed to create tap temp directory: {e}"))?;
            let tap_path = create_formula_copy(&temp_root, formula_path).unwrap();

            // We perform linting here too because we want to both
            // lint and runtest the `brew style --fix`ed version.
            // We're unable to check the fixed version into the
            // snapshots since it doesn't work cross-platform, so
            // doing them both in one place means we don't have to
            // run it twice.
            let output = brew_style(homebrew, &tap_path)?;
            if !output.status.success() {
                eprintln!("{}", String::from_utf8_lossy(&output.stdout));
                return Err(miette!("brew style found issues"));
            }

            eprintln!("running brew install...");
            homebrew.output_checked(|cmd| cmd.arg("install").arg(&tap_path))?;
            let prefix_output =
                homebrew.output_checked(|cmd| cmd.arg("--prefix").arg(&tap_path))?;
            let prefix_raw = String::from_utf8(prefix_output.stdout).unwrap();
            let prefix = prefix_raw.strip_suffix('\n').unwrap();
            let bin = Utf8PathBuf::from(&prefix).join("bin");

            for bin_name in ctx.options.bins_with_aliases(&self.app_name, &self.bins) {
                let bin_path = bin.join(bin_name);
                assert!(bin_path.exists(), "bin wasn't created");
            }

            homebrew.output_checked(|cmd| cmd.arg("uninstall").arg(tap_path))?;
        }
        Ok(())
    }
}

fn brew_repo_path(homebrew: &CommandInfo) -> Result<Utf8PathBuf> {
    let output = homebrew.output_checked(|cmd| cmd.arg("--repository"))?;

    let stdout = String::from_utf8(output.stdout)
        .map_err(|e| miette!("Failed to parse output as UTF-8: {}", e))?;

    Ok(Utf8PathBuf::from(stdout.trim()))
}

fn create_formula_copy(
    temp_root: &tempfile::TempDir,
    formula_path: &Utf8PathBuf,
) -> std::io::Result<PathBuf> {
    let formula_temp_root = temp_root.path().join("Formula");
    std::fs::create_dir(&formula_temp_root)?;
    let formula_temp_path = formula_temp_root.join(formula_path.file_name().unwrap());
    std::fs::copy(formula_path, &formula_temp_path)?;

    Ok(formula_temp_path)
}

fn brew_style(homebrew: &CommandInfo, path: &PathBuf) -> Result<Output> {
    homebrew.output(|cmd| {
        cmd.arg("style")
            // We ignore audits for user-supplied metadata,
            // since we avoid rewriting those on behalf of
            // the user. We also avoid the homepage nit,
            // because if the user doesn't supply a homepage
            // it's correct that we don't generate one.
            // We add FormulaAuditStrict because that's the
            // default exclusion, and adding anything to
            // --except-cops overrides it.
            .arg("--except-cops")
            .arg("FormulaAudit/Homepage,FormulaAudit/Desc,FormulaAuditStrict")
            // Applying --fix will ensure that fixable
            // style issues won't be treated as errors.
            .arg("--fix")
            .arg(path)
    })
}
