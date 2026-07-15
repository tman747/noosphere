use noos_nel::runtime::gguf::hex;
use noos_nel::runtime::inspect_bonsai;
use std::env;
use std::process::ExitCode;

fn main() -> ExitCode {
    let mut args = env::args_os();
    let program = args.next().unwrap_or_default();
    let Some(path) = args.next() else {
        eprintln!(
            "usage: {} <Bonsai-27B-Q1_0.gguf>",
            program.to_string_lossy()
        );
        return ExitCode::from(2);
    };
    if args.next().is_some() {
        eprintln!("noos-model-inspect accepts exactly one path");
        return ExitCode::from(2);
    }
    match inspect_bonsai(&path) {
        Ok(report) => {
            let value = &report.inspection;
            println!(
                concat!(
                    "{{\n",
                    "  \"status\": \"VERIFIED\",\n",
                    "  \"byte_length\": {},\n",
                    "  \"sha256\": \"{}\",\n",
                    "  \"gguf_version\": {},\n",
                    "  \"architecture\": \"{}\",\n",
                    "  \"model_name\": \"{}\",\n",
                    "  \"declared_context_tokens\": {},\n",
                    "  \"profile_max_context_tokens\": {},\n",
                    "  \"profile_max_output_tokens\": {},\n",
                    "  \"metadata_count\": {},\n",
                    "  \"tensor_count\": {},\n",
                    "  \"q1_tensor_count\": {},\n",
                    "  \"f32_tensor_count\": {},\n",
                    "  \"alignment\": {},\n",
                    "  \"data_offset\": {},\n",
                    "  \"tokenizer_model\": \"{}\",\n",
                    "  \"tokenizer_pretokenizer\": \"{}\",\n",
                    "  \"tokenizer_token_count\": {},\n",
                    "  \"tokenizer_merge_count\": {},\n",
                    "  \"bos_token_id\": {},\n",
                    "  \"eos_token_id\": {},\n",
                    "  \"padding_token_id\": {},\n",
                    "  \"metadata_root\": \"{}\",\n",
                    "  \"tensor_table_root\": \"{}\",\n",
                    "  \"tokenizer_root\": \"{}\",\n",
                    "  \"chat_template_root\": \"{}\",\n",
                    "  \"runtime_commit\": \"{}\",\n",
                    "  \"retained_header_bytes_upper_bound\": {},\n",
                    "  \"model_allocation_performed\": false\n",
                    "}}"
                ),
                value.stream.byte_length,
                hex(&value.stream.sha256),
                value.gguf_version,
                json_escape(&value.architecture),
                json_escape(&value.model_name),
                value.declared_context_tokens,
                report.max_context_tokens,
                report.max_output_tokens,
                value.metadata_count,
                value.tensor_count,
                value.q1_tensor_count,
                value.f32_tensor_count,
                value.alignment,
                value.data_offset,
                json_escape(&value.tokenizer_model),
                json_escape(&value.tokenizer_pretokenizer),
                value.tokenizer_token_count,
                value.tokenizer_merge_count,
                value.bos_token_id,
                value.eos_token_id,
                value.padding_token_id,
                hex(&value.metadata_root),
                hex(&value.tensor_table_root),
                hex(&value.tokenizer_root),
                hex(&value.chat_template_root),
                report.runtime_commit,
                value.retained_bytes_upper_bound(),
            );
            ExitCode::SUCCESS
        }
        Err(error) => {
            eprintln!("inspection failed: {error}");
            ExitCode::FAILURE
        }
    }
}

fn json_escape(value: &str) -> String {
    let mut output = String::with_capacity(value.len());
    for character in value.chars() {
        match character {
            '"' => output.push_str("\\\""),
            '\\' => output.push_str("\\\\"),
            '\n' => output.push_str("\\n"),
            '\r' => output.push_str("\\r"),
            '\t' => output.push_str("\\t"),
            character if character.is_control() => {
                use std::fmt::Write as _;
                let _ = write!(output, "\\u{:04x}", u32::from(character));
            }
            character => output.push(character),
        }
    }
    output
}
