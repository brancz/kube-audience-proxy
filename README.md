# kube-audience-proxy

A HTTP client proxy that transparently fetches and injects audience scoped Kubernetes ServiceAccount tokens.

## Motivation

Using Kubernetes' ServiceAccounts for authentication and authorization is an attractive option for securing Kubernetes cluster components as everything from auto-mounting over rotation is handled for you, but they're also easy to misuse as it was pointed out early when [kube-rbac-proxy](https://github.com/brancz/kube-rbac-proxy#notes-on-serviceaccount-token-security) was created. The problem is the same token that is used to authenticate against the Kubernetes API is used to authenticate against other endpoints, which allows said endpoints to impersonate the requesting entity by simply re-using the token it received.

As the same strategy that kube-rbac-proxy uses is used by Kubernetes components such as the kubelet, controller-manager and scheduler the Kubernetes project had to come up with a solution, and that solution is [Bound Service Account Tokens](https://github.com/kubernetes/enhancements/blob/master/keps/sig-auth/20190806-serviceaccount-tokens.md). Among other improvements over the initial ServiceAccount token design, Bound Service Account Tokens allows requesting a new token that is scoped to its audience preventing its use from anything but the target it was created for.

This project was initially created for use in combination with [Prometheus](https://prometheus.io/) and kube-rbac-proxy to create a more sound security story, but it can be used for any similar scenario.

## How

In its essence kube-audience-proxy is a very simple HTTP client proxy that simply transparently requests and injects bound tokens into a request. By default the audience is selected by specifying it in the `kubernetes-audience` query parameter of the client's HTTP request. In order for the proxy to intercept TLS connections, it generates and writes a CA at startup that the requesting entity needs to trust as it essentially needs to perform an intended man-in-the-middle attack, which is injecting the token.

## Security considerations

This proxy allows creating new tokens, while that's the main purpose, it's important to understand the implications of this. This proxy should likely never be exposed to anything but the client and the one client only that it's meant for. It is not recommended to share the proxy for multiple clients, instead use one proxy per client and bind the proxy against a loopback IP, and ensure that only the process it is meant for has access to it.

## Usage

The only thing that must be set is the `--service-account` flag, which for convenience defaults to the value of the `SERVICE_ACCOUNT` environment variable, so that can also be set instead of specifying the flag.

The kube-rbac-proxy has all [`klog`](https://github.com/golang/glog) flags for logging purposes of Kubernetes internal libraries and the `--log-level` flag for everything that makes up kube-audience-proxy.

If TLS connections are required, in which case the `--ca-file-destination` flag is important, as it is the location the proxy will write its generated CA certificate which the client needs to trust.

All command line flags:

[embedmd]:# (_output/help.txt)
```txt
$ kube-audience-proxy -h
Usage of _output/linux/amd64/kube-audience-proxy:
      --add_dir_header                   If true, adds the file directory to the header
      --alsologtostderr                  log to standard error as well as files
      --apiserver string                 Alternative apiserver so use.
      --audience-parameter string        Parameter name to read audience from to scope tokens to. (default "kubernetes-audience")
      --ca-file-destination string       File destination to write generated CA cert to. (default "ca.crt")
      --insecure-listen-address string   Address to bind HTTP server to.
      --insecure-skip-tls-verify          If true, the server's certificate will not be checked for validity. This will make your HTTPS connections insecure.
      --kubeconfig string                Kubeconfig to use to connect to cluster.
      --log-format string                Log format to use. Possible values: logfmt, json. (default "logfmt")
      --log-level string                 Log level to use. Possible values: all, debug, info, warn, error, none. (default "info")
      --log_backtrace_at traceLocation   when logging hits line file:N, emit a stack trace (default :0)
      --log_dir string                   If non-empty, write log files in this directory
      --log_file string                  If non-empty, use this log file
      --log_file_max_size uint           Defines the maximum size a log file can grow to. Unit is megabytes. If the value is 0, the maximum file size is unlimited. (default 1800)
      --logtostderr                      log to standard error instead of files (default true)
      --namespace-file string            File to read namespace of pod from. (default "/var/run/secrets/kubernetes.io/serviceaccount/namespace")
      --secure-listen-address string     Address to bind HTTPS server to.
      --service-account string           Name of serviceaccount of Pod the kube-audience-proxy process runs in.
      --skip_headers                     If true, avoid header prefixes in the log messages
      --skip_log_headers                 If true, avoid headers when opening log files
      --stderrthreshold severity         logs at or above this threshold go to stderr (default 2)
      --tls-cert-file string             File containing the default x509 Certificate for HTTPS. (CA cert, if any, concatenated after server cert)
      --tls-cipher-suites strings        Comma-separated list of cipher suites for the server. Values are from tls package constants (https://golang.org/pkg/crypto/tls/#pkg-constants). If omitted, the default Go cipher suites will be used
      --tls-min-version string           Minimum TLS version supported. Value must match version names from https://golang.org/pkg/crypto/tls/#pkg-constants. (default "VersionTLS12")
      --tls-private-key-file string      File containing the default x509 private key matching --tls-cert-file.
  -v, --v Level                          number for the log level verbosity
      --vmodule moduleSpec               comma-separated list of pattern=N settings for file-filtered logging
```
