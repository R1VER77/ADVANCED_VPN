//! Terminal prompts for setup and enrollment, delegated to the verified controller.

use std::io::{self, Write};

use anyhow::Result;
use serde_json::Value;

use crate::cloud;
use crate::controller::{Controller, is_root};
use crate::theme::Theme;

pub fn prompt(label: &str) -> io::Result<Option<String>> {
    print!("{label}");
    io::stdout().flush()?;
    let mut value = String::new();
    io::stdin().read_line(&mut value)?;
    let value = value.trim();
    Ok((!value.is_empty()).then(|| value.into()))
}

fn run(ctrl: &Controller, action: &str, args: &[String]) -> Result<bool> {
    Ok(ctrl.command(false, action, args).status()?.success())
}

pub fn setup(ctrl: &Controller, theme: Theme, reduced_motion: bool) -> Result<()> {
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
    println!("\nVPN setup\n");
    if enrolled == Some(true) {
        println!(
            "This device has a signed chain. You can keep it or install a replacement bundle."
        );
    }
    println!("1  {request_label}");
    println!("2  {enroll_label}");
    println!("3  Plan servers for your own chain");
    println!("4  Check this device and its next setup step");
    println!("5  Understand blocked traffic and the kill switch");
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
        println!(
            "In applications mode it covers apps started with cypherpunk run. In whole-device mode it covers the device's traffic."
        );
        println!(
            "Unlocking opens the device keys. Traffic is released when tunnel protection is verified."
        );
        println!(
            "Disconnect keeps the guard in place. To deliberately allow cleartext traffic, review cypherpunk help reset."
        );
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
    if run(ctrl, "enroll", &args)? {
        println!("The signed enrollment is installed. Press c in the VPN view to connect.");
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

pub fn locations(ctrl: &Controller) -> Result<()> {
    if !is_root() {
        println!("Open sudo cypherpunk and press l to manage signed chains.");
        return Ok(());
    }
    let mut filter: Option<(String, String)> = None;
    loop {
        let Some(data) = list(ctrl)? else {
            return Ok(());
        };
        println!("\nLocations\nCurrent enrollment");
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
        println!("1  Import a signed bundle");
        println!("2  Filter by country or city");
        println!("3  Select a saved chain");
        println!("4  Set a local hop location");
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
    println!("Disconnect first. The kill switch stays in place. Connect again when ready.");
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

pub fn settings(ctrl: &Controller, theme: Theme) -> Result<()> {
    if !is_root() {
        println!("Open sudo cypherpunk and press p to manage VPN settings.");
        return Ok(());
    }
    let info = ctrl.call("info", &[])?;
    let device = &info.value["info"];
    if device["enrolled"].as_bool() != Some(true) || device["role"].as_str() != Some("client") {
        println!("Set up an enrolled client with e before changing VPN settings.");
        return Ok(());
    }
    println!("\nVPN settings");
    println!(
        "1  Traffic scope · {}",
        device["mode"].as_str().unwrap_or("unknown")
    );
    println!("2  Launch a protected application");
    let cap = device["daily_limit_bytes"]
        .as_u64()
        .map_or_else(|| "none".into(), |n| format!("{} MiB", n / 1_048_576));
    println!("3  Daily traffic cap · {cap}");
    let upstream = device["upstream_interface"]
        .as_str()
        .unwrap_or("default route");
    let gateway = device["upstream_gateway"].as_str().unwrap_or("automatic");
    println!("4  Upstream interface · {upstream} (gateway {gateway})");
    println!("5  Kill-switch status and recovery");
    println!(
        "Signed rate class · {}",
        device["rate"].as_str().unwrap_or("unknown")
    );
    let args = match prompt("Choose a setting, or press Enter to go back: ")?.as_deref() {
        Some("1") => {
            match prompt("Protect 1 applications or 2 the whole device (Enter cancels): ")?
                .as_deref()
            {
                Some("1") => vec!["--mode=applications".into()],
                Some("2") => vec!["--mode=whole-device".into()],
                Some(_) => {
                    println!("Choose 1 or 2.");
                    return Ok(());
                }
                None => return Ok(()),
            }
        }
        Some("2") => {
            if let Some(program) = prompt("Executable name or path (Enter cancels): ")? {
                let mut argv = vec!["--".into(), program];
                while let Some(arg) = prompt("Next argument, or Enter to launch: ")? {
                    argv.push(arg);
                }
                println!("The VPN view returns after the application exits.");
                run(ctrl, "run", &argv)?;
            }
            return Ok(());
        }
        Some("3") => {
            match prompt("Daily cap in MiB (1–10240), none to remove it, or Enter to cancel: ")? {
                Some(cap) if cap == "none" => vec!["--no-daily-limit".into()],
                Some(cap) => vec![format!("--daily-limit-mib={cap}")],
                None => return Ok(()),
            }
        }
        Some("4") => {
            match prompt("Interface name, default to use normal routing, or Enter to cancel: ")? {
                Some(interface) if interface == "default" => vec!["--no-upstream".into()],
                Some(interface) => {
                    let mut args = vec![format!("--upstream-interface={interface}")];
                    if let Some(gateway) =
                        prompt("Gateway address, or Enter to use the interface's current route: ")?
                    {
                        args.push(format!("--upstream-gateway={gateway}"));
                    }
                    args
                }
                None => return Ok(()),
            }
        }
        Some("5") => {
            let done = crate::actions::perform(ctrl, "status", &[]);
            print!(
                "{}",
                crate::theme::to_ansi(&crate::cells::render(&done.cells, theme), theme)
            );
            println!(
                "The kill switch holds protected traffic until the tunnel is verified. Disconnect keeps it in place."
            );
            println!(
                "For deliberate cleartext recovery, disconnect, close protected apps, and review cypherpunk help reset."
            );
            return Ok(());
        }
        Some(_) => {
            println!("Choose a number from 1 through 5.");
            return Ok(());
        }
        None => return Ok(()),
    };
    if run(ctrl, "preferences", &args)? {
        println!("Saved. The preference applies on the next VPN connection.");
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
