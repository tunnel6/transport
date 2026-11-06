use serde_json::Value;

pub(crate) fn normalize_link_type(raw: &str) -> String {
  link_type_from_string(raw).unwrap_or("relay").to_string()
}

pub(crate) fn resolve_local_channel_link_type(transport: &str, metadata_json: &str) -> String {
  let fallback = normalize_link_type(transport);
  let raw = metadata_json.trim();
  if raw.is_empty() {
    return fallback;
  }

  let metadata: Value = match serde_json::from_str(raw) {
    Ok(parsed) => parsed,
    Err(_) => return fallback,
  };

  let policy_sources = [
    metadata.get("linkPolicy"),
    metadata.get("link_policy"),
    metadata.get("transportPolicy"),
    metadata.get("transport_policy"),
  ];
  for source in policy_sources {
    if let Some(link_type) = resolve_link_type_from_policy_source(source) {
      return link_type;
    }
  }

  if let Some(link_type) = first_link_type_from_array(metadata.get("preferred")) {
    return link_type.to_string();
  }
  if let Some(link_type) = first_link_type_from_array(metadata.get("preferred_links")) {
    return link_type.to_string();
  }
  if let Some(link_type) = metadata
    .get("link_type")
    .and_then(|item| item.as_str())
    .and_then(link_type_from_string)
  {
    return link_type.to_string();
  }
  if let Some(link_type) = metadata
    .get("linkType")
    .and_then(|item| item.as_str())
    .and_then(link_type_from_string)
  {
    return link_type.to_string();
  }

  fallback
}

pub(crate) fn is_chunked_complete(data: &[u8]) -> bool {
  if data.len() < 5 {
    return false;
  }

  data.windows(5).any(|w| w == b"0\r\n\r\n")
    || (data.len() >= 3 && &data[data.len() - 3..] == b"0\r\n")
}

pub(crate) fn parse_http_response(data: &[u8]) -> (u16, Vec<(String, String)>, Vec<u8>, String) {
  let response_str = match std::str::from_utf8(data) {
    Ok(s) => s,
    Err(_) => {
      return (200, vec![], data.to_vec(), String::new());
    }
  };

  let mut lines = response_str.lines();

  let status_code = if let Some(status_line) = lines.next() {
    let parts: Vec<&str> = status_line.split_whitespace().collect();
    if parts.len() >= 2 {
      parts[1].parse::<u16>().unwrap_or(200)
    } else {
      200
    }
  } else {
    200
  };

  let mut headers = Vec::new();
  let mut body_start = 0;

  for (_, line) in lines.enumerate() {
    if line.is_empty() {
      body_start = response_str[..]
        .find("\r\n\r\n")
        .or_else(|| response_str[..].find("\n\n"))
        .map(|pos| pos + 4)
        .unwrap_or(data.len());
      break;
    }

    if let Some(colon_pos) = line.find(':') {
      let key = line[..colon_pos].trim().to_string();
      let value = line[colon_pos + 1..].trim().to_string();
      headers.push((key, value));
    }
  }

  let body = if body_start < data.len() {
    data[body_start..].to_vec()
  } else {
    vec![]
  };

  (status_code, headers, body, String::new())
}

fn link_type_from_string(raw: &str) -> Option<&'static str> {
  match raw.trim().to_ascii_lowercase().as_str() {
    "p2p" => Some("p2p"),
    "wireguard" | "wg" => Some("wireguard"),
    "relay" => Some("relay"),
    _ => None,
  }
}

fn first_link_type_from_array(value: Option<&Value>) -> Option<&'static str> {
  let array = value.and_then(|item| item.as_array())?;
  for entry in array {
    let raw = match entry.as_str() {
      Some(item) => item,
      None => continue,
    };
    if let Some(link_type) = link_type_from_string(raw) {
      return Some(link_type);
    }
  }
  None
}

fn resolve_link_type_from_policy_source(value: Option<&Value>) -> Option<String> {
  let source = value?.as_object()?;
  if let Some(link_type) = first_link_type_from_array(source.get("preferred")) {
    return Some(link_type.to_string());
  }
  if let Some(link_type) = first_link_type_from_array(source.get("preferred_links")) {
    return Some(link_type.to_string());
  }
  if let Some(link_type) = source
    .get("link_type")
    .and_then(|item| item.as_str())
    .and_then(link_type_from_string)
  {
    return Some(link_type.to_string());
  }
  if let Some(link_type) = source
    .get("linkType")
    .and_then(|item| item.as_str())
    .and_then(link_type_from_string)
  {
    return Some(link_type.to_string());
  }
  None
}
