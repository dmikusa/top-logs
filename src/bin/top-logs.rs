use anyhow::{anyhow, Context, Result};
use clap::{app_from_crate, Arg};
use top_logs::TopInfo;

fn main() -> Result<()> {
    let app = app_from_crate!()
                    .arg(Arg::new("top")
                            .short('t')
                            .long("top")
                            .value_name("NUM")
                            .default_value("10")
                            .help("number of results to display")
                            .takes_value(true))
                    .arg(Arg::new("format")
                            .short('f')
                            .long("format")
                            .value_name("LOG_FORMAT")
                            .required(true)
                            .help("access log format")
                            .takes_value(true)
                            .possible_values(&["common", "combined", "gorouter", "cloud_controller"]))
                    .arg(Arg::new("ignore_parse_errors")
                            .short('i')
                            .long("ignore-parse-errors")
                            .help("Don't log any parsing error"))
                    .arg(Arg::new("min_response_time_threshold")
                            .short('m')
                            .long("min-response-time-threshold")
                            .value_name("MIN_THRESHOLD")
                            .help("Minimum threshold in number of requests for a response time bucket to be displayed. Smaller buckets are grouped together.")
                            .takes_value(true)
                            .default_value("100"))
                    .arg(Arg::new("access_logs")
                            .value_name("ACCESS_LOG")
                            .help("Access logs to process or '-' (a dash) to read from STDIN")
                            .index(1)
                            .multiple_occurrences(true)
                            .required(true)
                            .takes_value(true))
                    .get_matches();

    let mut ti = TopInfo::new(
        app.value_of("top")
            .unwrap()
            .parse()
            .with_context(|| "parsing top")?,
        app.is_present("ignore_parse_errors"),
    );

    for file in app.values_of("access_logs").unwrap() {
        ti.process_file(
            file,
            app.value_of("format")
                .unwrap()
                .parse()
                .map_err(|e| anyhow!("parse error: {}", e))
                .with_context(|| "parsing format")?,
        )?;
    }

    ti.print_summary(
        app.value_of("min_response_time_threshold")
            .unwrap()
            .parse()
            .with_context(|| "parsing min_response_time_threshold")?,
    );

    Ok(())
}
