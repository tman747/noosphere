resource "aws_cloudfront_cache_policy" "noos_wwm_shares" {
  name        = "noos-wwm-web-capacity-shares-v1"
  comment     = "Immutable identity-encoded WWM share bytes"
  default_ttl = 31536000
  max_ttl     = 31536000
  min_ttl     = 31536000

  parameters_in_cache_key_and_forwarded_to_origin {
    enable_accept_encoding_brotli = false
    enable_accept_encoding_gzip   = false

    cookies_config {
      cookie_behavior = "none"
    }
    headers_config {
      header_behavior = "none"
    }
    query_strings_config {
      query_string_behavior = "none"
    }
  }
}

resource "aws_cloudfront_response_headers_policy" "noos_wwm_shares" {
  name    = "noos-wwm-web-capacity-shares-v1"
  comment = "Wildcard CORS and immutable transport headers for public WWM shares"

  cors_config {
    access_control_allow_credentials = false
    access_control_max_age_sec        = 86400
    origin_override                   = true

    access_control_allow_headers {
      items = ["*"]
    }
    access_control_allow_methods {
      items = ["GET", "HEAD", "OPTIONS"]
    }
    access_control_allow_origins {
      items = ["*"]
    }
    access_control_expose_headers {
      items = ["Accept-Ranges", "Content-Length", "ETag"]
    }
  }

  custom_headers_config {
    items {
      header   = "Accept-Ranges"
      override = true
      value    = "bytes"
    }
    items {
      header   = "Cache-Control"
      override = true
      value    = "public, max-age=31536000, immutable, no-transform"
    }
    items {
      header   = "Content-Type"
      override = true
      value    = "application/octet-stream"
    }
  }

  security_headers_config {
    content_type_options {
      override = true
    }
  }
}

resource "aws_cloudfront_cache_policy" "noos_wwm_manifest" {
  name        = "noos-wwm-web-capacity-manifest-v1"
  comment     = "60-second signed WWM host manifest"
  default_ttl = 60
  max_ttl     = 60
  min_ttl     = 0
  parameters_in_cache_key_and_forwarded_to_origin {
    enable_accept_encoding_brotli = false
    enable_accept_encoding_gzip   = false

    cookies_config {
      cookie_behavior = "none"
    }
    headers_config {
      header_behavior = "none"
    }
    query_strings_config {
      query_string_behavior = "none"
    }
  }
}

resource "aws_cloudfront_response_headers_policy" "noos_wwm_manifest" {
  name    = "noos-wwm-web-capacity-manifest-v1"
  comment = "Wildcard CORS and 60-second revalidation for the signed WWM host manifest"

  cors_config {
    access_control_allow_credentials = false
    access_control_max_age_sec        = 300
    origin_override                   = true

    access_control_allow_headers {
      items = ["*"]
    }
    access_control_allow_methods {
      items = ["GET", "HEAD", "OPTIONS"]
    }
    access_control_allow_origins {
      items = ["*"]
    }
    access_control_expose_headers {
      items = ["Content-Length", "ETag"]
    }
  }

  custom_headers_config {
    items {
      header   = "Cache-Control"
      override = true
      value    = "public, max-age=60, must-revalidate"
    }
  }

  security_headers_config {
    content_type_options {
      override = true
    }
  }
}

resource "aws_cloudfront_cache_policy" "noos_wwm_inventory" {
  name        = "noos-wwm-web-capacity-inventory-v1"
  comment     = "Always-revalidated WWM inventory; publish before the signed manifest"
  default_ttl = 0
  max_ttl     = 0
  min_ttl     = 0

  parameters_in_cache_key_and_forwarded_to_origin {
    enable_accept_encoding_brotli = false
    enable_accept_encoding_gzip   = false

    cookies_config {
      cookie_behavior = "none"
    }
    headers_config {
      header_behavior = "none"
    }
    query_strings_config {
      query_string_behavior = "none"
    }
  }
}

resource "aws_cloudfront_response_headers_policy" "noos_wwm_inventory" {
  name    = "noos-wwm-web-capacity-inventory-v1"
  comment = "Wildcard CORS and mandatory revalidation for the mutable inventory path"

  cors_config {
    access_control_allow_credentials = false
    access_control_max_age_sec        = 300
    origin_override                   = true

    access_control_allow_headers {
      items = ["*"]
    }
    access_control_allow_methods {
      items = ["GET", "HEAD", "OPTIONS"]
    }
    access_control_allow_origins {
      items = ["*"]
    }
    access_control_expose_headers {
      items = ["Content-Length", "ETag"]
    }
  }

  custom_headers_config {
    items {
      header   = "Cache-Control"
      override = true
      value    = "public, max-age=0, no-cache, must-revalidate"
    }
  }

  security_headers_config {
    content_type_options {
      override = true
    }
  }
}

resource "aws_cloudfront_cache_policy" "noos_wwm_legal" {
  name        = "noos-wwm-web-capacity-legal-v1"
  comment     = "Immutable model license and NOTICE bytes"
  default_ttl = 31536000
  max_ttl     = 31536000
  min_ttl     = 31536000

  parameters_in_cache_key_and_forwarded_to_origin {
    enable_accept_encoding_brotli = false
    enable_accept_encoding_gzip   = false

    cookies_config {
      cookie_behavior = "none"
    }
    headers_config {
      header_behavior = "none"
    }
    query_strings_config {
      query_string_behavior = "none"
    }
  }
}

resource "aws_cloudfront_response_headers_policy" "noos_wwm_legal" {
  name    = "noos-wwm-web-capacity-legal-v1"
  comment = "Wildcard CORS and immutable caching for model license and NOTICE bytes"

  cors_config {
    access_control_allow_credentials = false
    access_control_max_age_sec        = 86400
    origin_override                   = true

    access_control_allow_headers {
      items = ["*"]
    }
    access_control_allow_methods {
      items = ["GET", "HEAD", "OPTIONS"]
    }
    access_control_allow_origins {
      items = ["*"]
    }
    access_control_expose_headers {
      items = ["Content-Length", "ETag"]
    }
  }

  custom_headers_config {
    items {
      header   = "Cache-Control"
      override = true
      value    = "public, max-age=31536000, immutable"
    }
  }

  security_headers_config {
    content_type_options {
      override = true
    }
  }
}
