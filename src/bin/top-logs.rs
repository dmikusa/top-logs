use anyhow::{anyhow, Context, Result};
use clap::{command, Arg, ArgAction};
use top_logs::TopInfo;

fn main() -> Result<()> {
    let app = command!()
                    .arg(Arg::new("top")
                            .short('t')
                            .long("top")
                            .value_name("NUM")
                            .default_value("10")
                            .help("number of results to display"))
                    .arg(Arg::new("format")
                            .short('f')
                            .long("format")
                            .value_name("LOG_FORMAT")
                            .required(true)
                            .help("access log format")
                            .value_parser(["common", "combined", "gorouter", "cloud_controller"]))
                    .arg(Arg::new("ignore_parse_errors")
                            .short('i')
                            .long("ignore-parse-errors")
                            .action(ArgAction::SetTrue)
                            .help("Don't log any parsing error"))
                    .arg(Arg::new("min_response_time_threshold")
                            .short('m')
                            .long("min-response-time-threshold")
                            .value_name("MIN_THRESHOLD")
                            .help("Minimum threshold in number of requests for a response time bucket to be displayed. Smaller buckets are grouped together.")
                            .default_value("100"))
                    .arg(Arg::new("access_logs")
                            .value_name("ACCESS_LOG")
                            .help("Access logs to process or '-' (a dash) to read from STDIN")
                            .index(1)
                            .action(ArgAction::Append)
                            .required(true))
                    .get_matches();

    let mut ti = TopInfo::new(
        app.get_one::<String>("top")
            .unwrap()
            .parse()
            .with_context(|| "parsing top")?,
        app.contains_id("ignore_parse_errors"),
    );

    for file in app.get_many::<String>("access_logs").unwrap() {
        ti.process_file(
            file,
            app.get_one::<String>("format")
                .unwrap()
                .parse()
                .map_err(|e| anyhow!("parse error: {}", e))
                .with_context(|| "parsing format")?,
        )?;
    }

    ti.print_summary(
        app.get_one::<String>("min_response_time_threshold")
            .unwrap()
            .parse()
            .with_context(|| "parsing min_response_time_threshold")?,
    );

    Ok(())
}
