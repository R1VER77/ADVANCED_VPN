//! Terminal prompts for setup and enrollment, delegated to the verified controller.

use std::io::{self, Write};

use anyhow::Result;
use ratatui::text::{Line, Span};
use serde_json::Value;

use crate::cloud;
use crate::controller::{Controller, is_root};
use crate::theme::Theme;

pub fn prompt(label: &str) -> io::Result<Option<String>> {
    Ok(read_prompt(label)?.filter(|value| !value.is_empty()))
}

fn read_prompt(label: &str) -> io::Result<Option<String>> {
    print!("{label}");
    io::stdout().flush()?;
    let mut value = String::new();
    let bytes = io::stdin().read_line(&mut value)?;
    Ok((bytes != 0).then(|| value.trim().into()))
}

fn run(ctrl: &Controller, action: &str, args: &[String]) -> Result<bool> {
    Ok(ctrl.command(false, action, args).status()?.success())
}

pub fn disarm(ctrl: &Controller, theme: Theme) -> Result<()> {
    if !is_root() {
        println!("Open sudo cypherpunk and choose /killswitch-disarm to recover internet access.");
        println!(
            "From a shell, run sudo cypherpunk disconnect, then sudo cypherpunk killswitch-disarm --allow-cleartext."
        );
        return Ok(());
    }
    heading(theme, "Restore internet access");
    println!(
        "This stops the VPN and restores ordinary internet access. Apps can then send traffic through your ISP."
    );
    println!("Close protected apps before continuing.");
    if prompt("Type allow cleartext to proceed, or press Enter to cancel: ")?.as_deref()
        != Some("allow cleartext")
    {
        return Ok(());
    }
    println!("Stopping the VPN…");
    let stopped = crate::actions::perform(ctrl, "disconnect", &["--keep-guard".into()]);
    print!(
        "{}",
        crate::theme::to_ansi(&crate::cells::render(&stopped.cells, theme), theme)
    );
    if stopped.code == 0 {
        println!("Restoring ordinary internet access…");
        run(ctrl, "reset", &["--allow-cleartext".into()])?;
    }
    Ok(())
}

pub fn setup(ctrl: &Controller, theme: Theme, reduced_motion: bool) -> Result<()> {
    println!("Reading this device's setup state…");
    let info = ctrl.call("info", &[])?;
    let device = &info.value["info"];
    let enrolled = device["enrolled"].as_bool();
    let has_keys = device["role"].is_string();
    let request_label = if has_keys {
        "Export the public request (keep existing keys)"
    } else {
        "Create a Nitrokey-protected client request"
    };
    let enroll_label = if enrolled == Some(true) {
        "Replace the enrolled chain"
    } else {
        "Install a signed enrollment bundle"
    };
    heading(theme, "VPN setup");
    if enrolled == Some(true) {
        println!(
            "This device has a signed chain. You can keep it or install a replacement bundle."
        );
    }
    row(theme, "1", request_label, "");
    row(theme, "2", enroll_label, "");
    row(theme, "3", "Plan servers for your own chain", "");
    row(theme, "4", "Check this device and its next setup step", "");
    row(
        theme,
        "5",
        "Understand blocked traffic and the kill switch",
        "",
    );
    let Some(choice) = prompt("Choose a step, or press Enter to go back: ")? else {
        return Ok(());
    };
    if choice == "3" {
        operator_plan(theme, reduced_motion)?;
        return Ok(());
    }
    if choice == "4" {
        run(ctrl, "setup", &[])?;
        return Ok(());
    }
    if choice == "5" {
        println!(
            "\nBlocked means the kill switch is holding protected traffic while the VPN cannot verify the path."
        );
        println!("The automatic kill switch protects the whole device during a VPN session.");
        println!(
            "Unlocking opens the device keys. Traffic is released when tunnel protection is verified."
        );
        println!("Lockdown keeps the guard in place after Disconnect. Press k to review it.");
        return Ok(());
    }
    if !matches!(choice.as_str(), "1" | "2") {
        println!("Choose a number from 1 through 5.");
        return Ok(());
    }
    if !is_root() || enrolled.is_none() {
        println!("Open sudo cypherpunk, then press e to manage this device's enrollment.");
        return Ok(());
    }
    if choice == "1" {
        let Some(path) = prompt("Where should the public request be saved? Enter a file path: ")?
        else {
            return Ok(());
        };
        let mut args = if has_keys {
            vec!["--existing".into()]
        } else {
            vec![
                "--role".into(),
                "client".into(),
                "--protect".into(),
                "nitrokey".into(),
            ]
        };
        if std::path::Path::new(&path).exists() {
            println!("Choose a new file path for the public request.");
            return Ok(());
        }
        args.push(format!("--out={path}"));
        println!("Preparing the device request…");
        if run(ctrl, "request", &args)? {
            println!(
                "Give the public request to your operator, or choose step 3 to plan your own chain."
            );
            println!(
                "Return to step 2 when you have the signed bundle and the operator's public key."
            );
        }
        return Ok(());
    }
    install_bundle(ctrl, enrolled == Some(true), device)
}

fn install_bundle(ctrl: &Controller, replace: bool, device: &Value) -> Result<()> {
    if device["role"].is_null() {
        println!(
            "Create a device request in step 1 first. The operator signs a bundle for those keys."
        );
        return Ok(());
    }
    if replace {
        println!("Disconnect the VPN first. The replacement uses this device's existing keys.");
    }
    let Some(bundle) = prompt("Path to the signed .cpvpn bundle: ")? else {
        return Ok(());
    };
    println!("Use the operator public key you obtained separately and verified.");
    let Some(key) = prompt("Path to the verified operator public key: ")? else {
        return Ok(());
    };
    let mut args = vec![format!("--operator-key={key}")];
    if replace {
        if prompt("Type replace to switch the enrolled chain, or press Enter to cancel: ")?
            .as_deref()
            != Some("replace")
        {
            return Ok(());
        }
        args.push("--replace".into());
    }
    args.extend(["--".into(), bundle]);
    println!("Verifying the operator signature and installing the enrollment…");
    if run(ctrl, "enroll", &args)? {
        println!("The signed enrollment is installed.");
        if !replace
            && device["role"].as_str() == Some("client")
            && !run(ctrl, "preferences", &["--mode=whole-device".into()])?
        {
            return Ok(());
        }
        println!("Press c in the VPN view to connect.");
    }
    Ok(())
}

fn operator_plan(theme: Theme, reduced_motion: bool) -> Result<()> {
    println!("\nSet up your own servers");
    println!("1. Export a client request from the setup menu.");
    println!(
        "2. Register or provision the relay and exit. See cypherpunk help cloud for provider and host commands."
    );
    println!(
        "3. Review the chain plan, sign it with your operator key, then install the signed client bundle."
    );
    if is_root() {
        println!(
            "Open cypherpunk as your normal user, then choose e and 3 to use your cloud sign-ins."
        );
        return Ok(());
    }
    println!("1  Discover server options");
    println!("2  Review and build a chain from registered servers");
    match prompt("Choose an operator action, or press Enter to go back: ")?.as_deref() {
        Some("1") => {
            cloud::main(&["suggest".into()], false, theme, reduced_motion);
        }
        Some("2") => {
            let Some(request) = prompt("Path to the client's public request: ")? else {
                return Ok(());
            };
            let Some(vault) = prompt("Path to the operator's Nitrokey vault: ")? else {
                return Ok(());
            };
            let args = [
                "chain".into(),
                "--apply".into(),
                format!("--client-request={request}"),
                format!("--vault={vault}"),
            ];
            cloud::main(&args, false, theme, reduced_motion);
        }
        Some(_) => println!("Choose 1 or 2 from the operator menu."),
        None => {}
    }
    Ok(())
}

fn print_route(hops: &Value) {
    for hop in hops.as_array().into_iter().flatten() {
        println!(
            "  {}  {} · {}",
            crate::cells::hop_role(hop),
            crate::cells::hop_place(hop),
            hop["endpoint"].as_str().unwrap_or("unknown endpoint")
        );
    }
}

fn matches_location(route: &Value, role: &str, query: &str) -> bool {
    let query = query.to_lowercase();
    let hops = route.as_array().map(Vec::as_slice).unwrap_or_default();
    hops.iter().enumerate().any(|(index, hop)| {
        let matching_role = match role {
            "entry" => index == 0,
            "middle" | "exit" => hop["hop"].as_str() == Some(role),
            _ => true,
        };
        matching_role
            && ["country", "country_code", "city"].iter().any(|key| {
                hop[key]
                    .as_str()
                    .is_some_and(|s| s.to_lowercase().contains(&query))
            })
    })
}

fn list(ctrl: &Controller) -> Result<Option<Value>> {
    let response = ctrl.call("chains", &["list".into()])?;
    if response.ok() {
        return Ok(Some(response.value));
    }
    let detail = response.value["message"]
        .as_str()
        .unwrap_or("Check enrollment with e setup.");
    println!("Cannot list signed chains. {detail}");
    Ok(None)
}

pub fn locations(ctrl: &Controller, theme: Theme) -> Result<()> {
    if !is_root() {
        println!("Open sudo cypherpunk and press l to manage signed chains.");
        return Ok(());
    }
    let mut filter: Option<(String, String)> = None;
    loop {
        let Some(data) = list(ctrl)? else {
            return Ok(());
        };
        heading(theme, "Locations");
        println!("  Current enrollment");
        print_route(&data["current"]);
        if let Some((role, query)) = &filter {
            println!("Saved chains matching {role} / {query}");
        } else {
            println!("Saved signed chains");
        }
        let rows = data["saved"]
            .as_array()
            .map(Vec::as_slice)
            .unwrap_or_default();
        let mut shown = false;
        for row in rows.iter().filter(|row| {
            filter
                .as_ref()
                .is_none_or(|(role, query)| matches_location(&row["hops"], role, query))
        }) {
            shown = true;
            let name = row["name"].as_str().unwrap_or_default();
            let status = if row["active"].as_bool() == Some(true) {
                " (current)"
            } else if row["available"].as_bool() != Some(true) {
                " (unavailable)"
            } else {
                ""
            };
            println!("{name}{status}");
            print_route(&row["hops"]);
        }
        if !shown {
            println!("No matching saved chains. Import a bundle or change the filter.");
        }
        row(theme, "1", "Import a signed bundle", "");
        row(theme, "2", "Filter by country or city", "");
        row(theme, "3", "Select a saved chain", "");
        row(theme, "4", "Set a local hop location", "");
        match prompt("Choose an action, or press Enter to go back: ")?.as_deref() {
            Some("1") => {
                if let Some(name) =
                    prompt("Name for this chain (lowercase, digits, hyphens or underscores): ")?
                    && let Some(path) =
                        prompt("Path to the signed bundle from your enrolled operator: ")?
                {
                    run(ctrl, "chains", &["import".into(), name, "--".into(), path])?;
                }
            }
            Some("2") => {
                let role = prompt("Which hop? entry, middle, exit, or Enter for any: ")?
                    .unwrap_or_else(|| "any".into());
                if !matches!(role.as_str(), "entry" | "middle" | "exit" | "any") {
                    println!("Choose entry, middle, exit or any.");
                    continue;
                }
                filter = prompt("Country name, two-letter code, or city (Enter clears filter): ")?
                    .map(|query| (role, query));
            }
            Some("3") => {
                if let Some(name) = prompt("Saved chain name: ")? {
                    select_saved(ctrl, &data, name)?;
                }
            }
            Some("4") => {
                let Some(hop) = prompt("Hop to label (entry, middle or exit): ")? else {
                    continue;
                };
                let route = prompt("Saved chain name, or Enter for the current enrollment: ")?;
                let Some(country) = prompt("Two-letter country code, for example DE: ")? else {
                    continue;
                };
                let city = prompt("City name, or Enter if unknown: ")?;
                let mut args = vec![
                    "location".into(),
                    "set".into(),
                    hop,
                    format!("--country={country}"),
                ];
                if let Some(city) = city {
                    args.push(format!("--city={city}"));
                }
                if let Some(route) = route {
                    args.push(format!("--chain={route}"));
                }
                run(ctrl, "chains", &args)?;
            }
            Some(_) => println!("Choose a number from 1 through 4."),
            None => return Ok(()),
        }
    }
}

fn select_saved(ctrl: &Controller, listing: &Value, name: String) -> Result<()> {
    let Some(row) = listing["saved"]
        .as_array()
        .into_iter()
        .flatten()
        .find(|row| {
            row["name"].as_str() == Some(&name) && row["available"].as_bool() == Some(true)
        })
    else {
        println!("Choose an available saved chain.");
        return Ok(());
    };
    if row["active"].as_bool() == Some(true) {
        println!("This chain is already selected.");
        return Ok(());
    }
    println!("Route to select");
    print_route(&row["hops"]);
    println!("Disconnect first. Lockdown determines whether ordinary internet access resumes.");
    let mut args = vec!["select".into(), name];
    if listing["active_saved"].as_bool() != Some(true) {
        println!(
            "The current route has no saved bundle. Import the original bundle before leaving it if you want to switch back."
        );
        if prompt("Type leave unsaved to continue, or press Enter to cancel: ")?.as_deref()
            != Some("leave unsaved")
        {
            return Ok(());
        }
        args.push("--allow-unsaved-current".into());
    } else if prompt("Type switch to confirm, or press Enter to cancel: ")?.as_deref()
        != Some("switch")
    {
        return Ok(());
    }
    run(ctrl, "chains", &args)?;
    Ok(())
}

fn heading(theme: Theme, title: &str) {
    println!();
    print!(
        "{}",
        crate::theme::to_ansi(&[Line::styled(title, theme.brand())], theme)
    );
}

fn row(theme: Theme, key: &str, label: &str, value: &str) {
    let line = Line::from(vec![
        Span::styled(format!("  {key:>2}  "), theme.accent()),
        Span::raw(format!("{label:<23}")),
        Span::styled(value, theme.dim()),
    ]);
    print!("{}", crate::theme::to_ansi(&[line], theme));
}

fn menu_prompt(theme: Theme, label: &str) -> io::Result<Option<String>> {
    let rendered = crate::theme::to_ansi(&[Line::styled(label, theme.accent())], theme);
    prompt(rendered.trim_end_matches('\n'))
}

pub fn connect(ctrl: &Controller, theme: Theme) -> Result<bool> {
    let outcome = ctrl.call("info", &[])?;
    let info = &outcome.value["info"];
    row(
        theme,
        "◌",
        "Starting VPN",
        scope_label(info["mode"].as_str()),
    );
    let done = crate::actions::perform(ctrl, "connect", &[]);
    print!(
        "{}",
        crate::theme::to_ansi(&crate::cells::render(&done.cells, theme), theme)
    );
    if done.code != 0 {
        return Ok(false);
    }
    if info["protection"].as_str() == Some("nitrokey") {
        return run(ctrl, "unlock", &["--if-needed".into()]);
    }
    Ok(true)
}

fn scope_label(mode: Option<&str>) -> &str {
    if mode == Some("applications") {
        "Applications"
    } else {
        "Whole device"
    }
}

pub fn switch_scope(ctrl: &Controller, theme: Theme) -> Result<()> {
    if !is_root() {
        println!("Open sudo cypherpunk to change scope.");
        return Ok(());
    }
    let response = ctrl.call("info", &[])?;
    let device = &response.value["info"];
    if device["role"].as_str() != Some("client") || device["enrolled"].as_bool() != Some(true) {
        println!("Set up an enrolled client before changing scope.");
        return Ok(());
    }
    let next = if device["mode"].as_str() == Some("applications") {
        "whole-device"
    } else {
        "applications"
    };
    let disable_lockdown = next == "applications" && device["lockdown"].as_bool() == Some(true);
    let live = &device["status"];
    let running = matches!(
        live["state"].as_str(),
        Some("supervising" | "waiting for the Nitrokey PIN")
    ) || live["children"].is_object();
    heading(theme, "Traffic scope");
    row(theme, "→", "Switch to", scope_label(Some(next)));
    if next == "applications" {
        println!(
            "      Only apps launched from /applications use the VPN. Other apps use your normal connection."
        );
    }
    if disable_lockdown {
        println!(
            "      This switch turns off Lockdown. Close any open protected apps before proceeding."
        );
    }
    let question = if running {
        "  Switch and reconnect now? [y/N] "
    } else {
        "  Save this scope for the next connection? [y/N] "
    };
    if menu_prompt(theme, question)?.as_deref() != Some("y") {
        return Ok(());
    }
    if running || next == "applications" {
        // Keeping the whole-device firewall when entering Applications would
        // block ordinary apps. The confirmed policy change may release it.
        let keep_guard = ["--keep-guard".into()];
        let args = if next == "whole-device" || disable_lockdown {
            &keep_guard[..]
        } else {
            &[]
        };
        let stopped = crate::actions::perform(ctrl, "disconnect", args);
        print!(
            "{}",
            crate::theme::to_ansi(&crate::cells::render(&stopped.cells, theme), theme)
        );
        if stopped.code != 0 {
            return Ok(());
        }
    }
    if disable_lockdown && !run(ctrl, "preferences", &["--lockdown=off".into()])? {
        return Ok(());
    }
    if run(ctrl, "preferences", &[format!("--mode={next}")])? && running {
        connect(ctrl, theme)?;
    }
    Ok(())
}

pub fn applications(ctrl: &Controller, theme: Theme) -> Result<()> {
    if !is_root() {
        println!("Open sudo cypherpunk to manage protected applications.");
        return Ok(());
    }
    loop {
        let response = ctrl.call("info", &[])?;
        let device = &response.value["info"];
        if device["role"].as_str() != Some("client") || device["enrolled"].as_bool() != Some(true) {
            println!("Set up an enrolled client before choosing protected applications.");
            return Ok(());
        }
        let apps: Vec<_> = device["protected_apps"]
            .as_array()
            .into_iter()
            .flatten()
            .filter_map(Value::as_str)
            .collect();
        heading(theme, "Protected applications");
        println!(
            "      Applications mode protects launches from this list. Apps opened normally use your regular connection."
        );
        for (index, executable) in apps.iter().enumerate() {
            row(theme, &(index + 1).to_string(), executable, "");
        }
        println!("      a add · r remove · number launch · Enter back");
        let Some(choice) = menu_prompt(theme, "  Choose an application or action: ")? else {
            return Ok(());
        };
        if choice == "a" {
            if let Some(executable) = menu_prompt(theme, "  Executable name or absolute path: ")? {
                run(
                    ctrl,
                    "preferences",
                    &[format!("--protect-app={executable}")],
                )?;
            }
            continue;
        }
        let removing = choice == "r";
        let selection = if removing {
            menu_prompt(theme, "  Number to remove: ")?
        } else {
            Some(choice)
        };
        let Some(executable) = selection
            .as_deref()
            .and_then(|number| number.parse::<usize>().ok())
            .and_then(|index| index.checked_sub(1))
            .and_then(|index| apps.get(index))
        else {
            println!("      Choose a number from the list.");
            continue;
        };
        if removing {
            run(ctrl, "preferences", &[format!("--forget-app={executable}")])?;
            continue;
        }
        if device["status"]["scope"].as_str() != Some("applications")
            || device["status"]["protection"].as_str() != Some("protected")
        {
            println!(
                "      Connect in Applications mode and wait for protection before launching."
            );
            continue;
        }
        println!(
            "      Close any ordinary instance first. The launcher opens a new process inside the VPN."
        );
        let mut argv = vec!["--".into(), (*executable).into()];
        while let Some(argument) =
            menu_prompt(theme, "  Add one argument, or press Enter to launch: ")?
        {
            argv.push(argument);
        }
        println!("      Waiting for the application to exit. Its traffic is isolated by the VPN.");
        run(ctrl, "run", &argv)?;
    }
}

pub fn lockdown(ctrl: &Controller, theme: Theme) -> Result<()> {
    if !is_root() {
        println!("Open sudo cypherpunk to change Lockdown.");
        return Ok(());
    }
    row(theme, "◌", "Reading Lockdown", "");
    let info = ctrl.call("info", &[])?;
    let device = &info.value["info"];
    if device["lockdown"].as_bool().is_none() {
        println!("Set up an enrolled client before changing Lockdown.");
        return Ok(());
    }
    let enabled = device["lockdown"].as_bool() == Some(true);
    let next = if enabled { "off" } else { "on" };
    let status = &device["status"];
    let running = matches!(
        status["state"].as_str(),
        Some("supervising" | "waiting for the Nitrokey PIN")
    ) || status["children"].is_object();
    heading(theme, "Network protection");
    row(
        theme,
        "✓",
        "Automatic kill switch",
        "On while connecting, connected or reconnecting",
    );
    row(theme, "1", "Lockdown", if enabled { "On" } else { "Off" });
    println!("      Lockdown blocks ordinary internet access after Disconnect and at startup.");
    if menu_prompt(theme, "  Press 1 to change Lockdown, or Enter to go back: ")?.as_deref()
        != Some("1")
    {
        return Ok(());
    }
    if enabled {
        println!("      Turning Lockdown off permits ISP traffic while the VPN is disconnected.");
    }
    let verb = if running { "reconnect" } else { "apply" };
    println!(
        "      Turn Lockdown {next}{}?",
        if running { " and reconnect now" } else { "" }
    );
    if menu_prompt(
        theme,
        &format!("  Type {verb} to continue, or Enter to cancel: "),
    )?
    .as_deref()
        != Some(verb)
    {
        return Ok(());
    }
    if running {
        let stopped = crate::actions::perform(ctrl, "disconnect", &["--keep-guard".into()]);
        print!(
            "{}",
            crate::theme::to_ansi(&crate::cells::render(&stopped.cells, theme), theme)
        );
        if stopped.code != 0 {
            return Ok(());
        }
    }
    let mut args = vec![format!("--lockdown={next}")];
    if running && enabled {
        args.push("--keep-guard".into());
    }
    if run(ctrl, "preferences", &args)? && running {
        connect(ctrl, theme)?;
    }
    Ok(())
}

pub fn settings(ctrl: &Controller, theme: Theme) -> Result<()> {
    if !is_root() {
        println!("Open sudo cypherpunk and press p to manage VPN settings.");
        return Ok(());
    }
    row(theme, "◌", "Reading VPN settings", "");
    let info = ctrl.call("info", &[])?;
    let device = &info.value["info"];
    if device["enrolled"].as_bool() != Some(true) || device["role"].as_str() != Some("client") {
        println!("Set up an enrolled client with e before changing VPN settings.");
        return Ok(());
    }
    heading(theme, "VPN settings");
    row(
        theme,
        "4",
        "Traffic scope",
        scope_label(device["mode"].as_str()),
    );
    row(
        theme,
        "5",
        "Protected applications",
        "Choose which apps to launch through the VPN",
    );
    row(
        theme,
        "",
        "Automatic kill switch",
        "Always on during a VPN session",
    );
    row(
        theme,
        "1",
        "Lockdown",
        if device["lockdown"].as_bool() == Some(true) {
            "On"
        } else {
            "Off"
        },
    );
    let cap = device["daily_limit_bytes"]
        .as_u64()
        .map_or_else(|| "None".into(), |n| format!("{} MiB", n / 1_048_576));
    row(theme, "2", "Daily traffic cap", &cap);
    row(
        theme,
        "3",
        "Upstream interface",
        device["upstream_interface"]
            .as_str()
            .unwrap_or("Default route"),
    );
    row(
        theme,
        "",
        "Signed rate class",
        device["rate"].as_str().unwrap_or("Unknown"),
    );
    println!();
    let args =
        match menu_prompt(theme, "  Choose a setting, or press Enter to go back: ")?.as_deref() {
            Some("1") => return lockdown(ctrl, theme),
            Some("4") => return switch_scope(ctrl, theme),
            Some("5") => return applications(ctrl, theme),
            Some("2") => match menu_prompt(
                theme,
                "  Daily cap in MiB (1–10240), none to remove, or Enter to cancel: ",
            )?
            .as_deref()
            {
                Some("none") => vec!["--no-daily-limit".into()],
                Some(cap) => vec![format!("--daily-limit-mib={cap}")],
                None => return Ok(()),
            },
            Some("3") => match menu_prompt(
                theme,
                "  Interface name, default to use normal routing, or Enter to cancel: ",
            )?
            .as_deref()
            {
                Some("default") => vec!["--no-upstream".into()],
                Some(interface) => {
                    let mut args = vec![format!("--upstream-interface={interface}")];
                    if let Some(gateway) =
                        menu_prompt(theme, "  Gateway address, or Enter for automatic: ")?
                    {
                        args.push(format!("--upstream-gateway={gateway}"));
                    }
                    args
                }
                None => return Ok(()),
            },
            Some(_) => {
                println!("  Choose 1 through 5.");
                return Ok(());
            }
            None => return Ok(()),
        };
    if run(ctrl, "preferences", &args)? {
        println!("  Saved. Changes apply on the next connection.");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::matches_location;
    use serde_json::json;

    #[test]
    fn filters_the_selected_hop_by_name_code_and_city() {
        let route = json!([
            {"hop":"relay","country":"United Arab Emirates","country_code":"AE","city":"Dubai"},
            {"hop":"middle","country":null,"city":null},
            {"hop":"exit","country":"Germany","country_code":"DE","city":"Frankfurt"}
        ]);
        assert!(matches_location(&route, "entry", "dUbAi"));
        assert!(matches_location(&route, "exit", "DE"));
        assert!(matches_location(&route, "any", "Germany"));
        assert!(!matches_location(&route, "entry", "Frankfurt"));
        assert!(!matches_location(&route, "middle", "Unknown"));
    }
}
