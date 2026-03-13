using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Net;
using System.Net.Cache;
using System.Text;
using CommunitySDK;

namespace HttpRequests.Background
{
    internal class HttpRequestConfig
    {
        public string Name;
        public string HttpMethod;
        public string Url;
        public string PayloadType;
        public string Body;
        public Dictionary<string, string> Headers;
        public Dictionary<string, string> QueryParams;
        public bool SkipCertValidation;
        public int TimeoutMs;
        public string AuthType;
        public string AuthUsername;
        public string AuthPassword;
        public string AuthToken;
    }

    internal class HttpRequestResult
    {
        public int StatusCode;
        public string ResponseBody;
        public long ElapsedMs;
        public bool Success;
        public string Error;
    }

    internal static class HttpRequestExecutor
    {
        private static readonly PluginLog _log = new PluginLog("HttpRequests.Executor");

        public static HttpRequestResult Execute(HttpRequestConfig config)
        {
            var sw = Stopwatch.StartNew();
            try
            {
                // Build URL with query params
                var url = BuildUrlWithParams(config.Url, config.QueryParams);

                // SSRF protection: block requests to loopback, private, and link-local addresses
                var ssrfError = CheckForSsrf(url);
                if (ssrfError != null)
                {
                    sw.Stop();
                    return new HttpRequestResult
                    {
                        StatusCode = 0,
                        ElapsedMs = sw.ElapsedMilliseconds,
                        Success = false,
                        Error = ssrfError
                    };
                }

                var request = (HttpWebRequest)WebRequest.Create(url);
                request.Method = config.HttpMethod;
                request.Timeout = config.TimeoutMs > 0 ? config.TimeoutMs : 10000;
                request.CachePolicy = new RequestCachePolicy(RequestCacheLevel.NoCacheNoStore);

                if (config.SkipCertValidation)
                {
                    _log.Info($"WARNING: TLS certificate validation disabled for request to {new Uri(url).Host}");
                    request.ServerCertificateValidationCallback = (sender, cert, chain, errors) => true;
                }

                // Authentication
                ApplyAuth(request, config);

                // Custom headers
                if (config.Headers != null)
                {
                    foreach (var kvp in config.Headers)
                    {
                        switch (kvp.Key.ToLowerInvariant())
                        {
                            case "content-type":
                                request.ContentType = kvp.Value;
                                break;
                            case "accept":
                                request.Accept = kvp.Value;
                                break;
                            case "user-agent":
                                request.UserAgent = kvp.Value;
                                break;
                            default:
                                request.Headers[kvp.Key] = kvp.Value;
                                break;
                        }
                    }
                }

                // Body
                if (!string.IsNullOrEmpty(config.Body) &&
                    config.HttpMethod != "GET" && config.HttpMethod != "DELETE")
                {
                    if (request.ContentType == null)
                        request.ContentType = GetContentType(config.PayloadType);

                    var bodyBytes = Encoding.UTF8.GetBytes(config.Body);
                    request.ContentLength = bodyBytes.Length;

                    using (var stream = request.GetRequestStream())
                    {
                        stream.Write(bodyBytes, 0, bodyBytes.Length);
                    }
                }

                using (var response = (HttpWebResponse)request.GetResponse())
                {
                    sw.Stop();
                    string responseBody;
                    using (var reader = new StreamReader(response.GetResponseStream(), Encoding.UTF8))
                    {
                        responseBody = reader.ReadToEnd();
                    }

                    return new HttpRequestResult
                    {
                        StatusCode = (int)response.StatusCode,
                        ResponseBody = responseBody,
                        ElapsedMs = sw.ElapsedMilliseconds,
                        Success = true
                    };
                }
            }
            catch (WebException wex)
            {
                sw.Stop();

                if (wex.Response is HttpWebResponse errorResponse)
                {
                    string errorBody;
                    using (var reader = new StreamReader(errorResponse.GetResponseStream(), Encoding.UTF8))
                    {
                        errorBody = reader.ReadToEnd();
                    }

                    return new HttpRequestResult
                    {
                        StatusCode = (int)errorResponse.StatusCode,
                        ResponseBody = errorBody,
                        ElapsedMs = sw.ElapsedMilliseconds,
                        Success = false,
                        Error = $"HTTP {(int)errorResponse.StatusCode}: {errorResponse.StatusDescription}"
                    };
                }

                return new HttpRequestResult
                {
                    StatusCode = 0,
                    ElapsedMs = sw.ElapsedMilliseconds,
                    Success = false,
                    Error = wex.Message
                };
            }
            catch (Exception ex)
            {
                sw.Stop();
                return new HttpRequestResult
                {
                    StatusCode = 0,
                    ElapsedMs = sw.ElapsedMilliseconds,
                    Success = false,
                    Error = ex.Message
                };
            }
        }

        private static void ApplyAuth(HttpWebRequest request, HttpRequestConfig config)
        {
            if (string.IsNullOrEmpty(config.AuthType) || config.AuthType == "None")
                return;

            switch (config.AuthType)
            {
                case "Basic":
                    var credentials = (config.AuthUsername ?? "") + ":" + (config.AuthPassword ?? "");
                    var basicToken = Convert.ToBase64String(Encoding.UTF8.GetBytes(credentials));
                    request.Headers["Authorization"] = "Basic " + basicToken;
                    break;

                case "Bearer":
                    request.Headers["Authorization"] = "Bearer " + (config.AuthToken ?? "");
                    break;

                case "Digest":
                    if (!string.IsNullOrEmpty(config.AuthUsername))
                    {
                        var credCache = new CredentialCache();
                        credCache.Add(new Uri(config.Url), "Digest",
                            new NetworkCredential(config.AuthUsername ?? "", config.AuthPassword ?? ""));
                        request.Credentials = credCache;
                        request.PreAuthenticate = true;
                    }
                    break;
            }
        }

        private static string GetContentType(string payloadType)
        {
            switch (payloadType)
            {
                case "JSON": return "application/json; charset=utf-8";
                case "XML": return "application/xml; charset=utf-8";
                case "Plain Text": return "text/plain; charset=utf-8";
                case "CSV": return "text/csv; charset=utf-8";
                default: return "text/plain; charset=utf-8";
            }
        }

        private static string BuildUrlWithParams(string baseUrl, Dictionary<string, string> queryParams)
        {
            if (queryParams == null || queryParams.Count == 0)
                return baseUrl;

            var sb = new StringBuilder(baseUrl);
            sb.Append(baseUrl.Contains("?") ? "&" : "?");
            bool first = true;
            foreach (var kvp in queryParams)
            {
                if (!first) sb.Append("&");
                sb.Append(Uri.EscapeDataString(kvp.Key));
                sb.Append("=");
                sb.Append(Uri.EscapeDataString(kvp.Value));
                first = false;
            }
            return sb.ToString();
        }

        /// <summary>
        /// Checks whether the target URL resolves to a loopback, private, or
        /// link-local address (SSRF protection). Returns an error message if
        /// blocked, or null if the URL is allowed.
        /// </summary>
        private static string CheckForSsrf(string url)
        {
            try
            {
                var uri = new Uri(url);
                var host = uri.Host;

                IPAddress[] addresses;
                try
                {
                    addresses = System.Net.Dns.GetHostAddresses(host);
                }
                catch
                {
                    return $"Cannot resolve hostname: {host}";
                }

                foreach (var addr in addresses)
                {
                    if (IPAddress.IsLoopback(addr))
                        return $"Requests to loopback addresses are not allowed ({addr})";

                    var bytes = addr.GetAddressBytes();

                    if (addr.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork && bytes.Length == 4)
                    {
                        // 10.0.0.0/8
                        if (bytes[0] == 10)
                            return $"Requests to private network addresses are not allowed ({addr})";

                        // 172.16.0.0/12
                        if (bytes[0] == 172 && bytes[1] >= 16 && bytes[1] <= 31)
                            return $"Requests to private network addresses are not allowed ({addr})";

                        // 192.168.0.0/16
                        if (bytes[0] == 192 && bytes[1] == 168)
                            return $"Requests to private network addresses are not allowed ({addr})";

                        // 169.254.0.0/16 (link-local, includes cloud metadata endpoints)
                        if (bytes[0] == 169 && bytes[1] == 254)
                            return $"Requests to link-local addresses are not allowed ({addr})";

                        // 127.0.0.0/8
                        if (bytes[0] == 127)
                            return $"Requests to loopback addresses are not allowed ({addr})";
                    }

                    if (addr.AddressFamily == System.Net.Sockets.AddressFamily.InterNetworkV6)
                    {
                        // ::1
                        if (addr.Equals(IPAddress.IPv6Loopback))
                            return $"Requests to loopback addresses are not allowed ({addr})";

                        // fe80::/10 link-local
                        if (bytes.Length >= 2 && bytes[0] == 0xfe && (bytes[1] & 0xc0) == 0x80)
                            return $"Requests to link-local addresses are not allowed ({addr})";

                        // fc00::/7 unique local
                        if (bytes.Length >= 1 && (bytes[0] & 0xfe) == 0xfc)
                            return $"Requests to private network addresses are not allowed ({addr})";
                    }
                }
            }
            catch (UriFormatException)
            {
                return "Invalid URL format";
            }

            return null;
        }
    }
}
