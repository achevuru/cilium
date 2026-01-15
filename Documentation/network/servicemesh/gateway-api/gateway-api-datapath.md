# Cilium Gateway API datapath walkthrough (default vs host-network)

This document consolidates the Gateway API behavior discussed across code and docs into a single, presentation-ready narrative. It focuses on **how the external load balancer is created**, **how traffic reaches Envoy**, and **why certain data path choices are required**.

---

## 1) Load balancer creation: default vs host-network

### Default (non-host-network) mode
The Gateway API controller (Cilium Operator) creates a Kubernetes **Service** for each Gateway. The Service **defaults to type `LoadBalancer`** unless host-network mode is enabled.

```go
// If hostNetwork is enabled, it returns ServiceTypeClusterIP. The default value is ServiceTypeLoadBalancer.
func (t *gatewayAPITranslator) toServiceType(params *model.Service) corev1.ServiceType {
	if t.cfg.HostNetworkConfig.Enabled {
		return corev1.ServiceTypeClusterIP
	}
	if params == nil {
		return corev1.ServiceTypeLoadBalancer
	}
	return corev1.ServiceType(params.Type)
}
```

Because the Service is type `LoadBalancer`, the **cloud provider’s load balancer controller/CCM** is expected to provision the external LB for that Service.

### Host-network mode
Host-network mode **disables the LoadBalancer Service mode** and **binds listeners directly on node interfaces**. The doc states these are mutually exclusive:

```rst
* Enabling the Cilium Gateway API host network mode automatically disables the LoadBalancer type Service mode. They are mutually exclusive.
* The listener is exposed on all interfaces (0.0.0.0 for IPv4 and/or :: for IPv6).
```

So in host-network mode:
- The Service type is **ClusterIP** (per the translator logic above).
- There is **no Service-based external LB** created; external routing/LB must be provisioned outside the Service model.

---

## 2) Default (non-host-network) datapath

### Diagram
```
External Client
   |
   v
[External LB]
   |
   v
Node IP + Service Port
   |
   v
[eBPF intercepts Service traffic]
   |
   v
TPROXY redirect --> Local Envoy (per-node)
   |
   v
Envoy opens upstream connection to backend Pod
   |
   v
Backend replies to Envoy -> Envoy replies to Client
```

### Key behavior from docs
The ingress reference describes how traffic reaches Envoy when exposed via LoadBalancer or NodePort:

```rst
Cilium's Ingress and Gateway API config is exposed with a Loadbalancer or NodePort
service, or optionally can be exposed on the Host network also. But in all of
these cases, when traffic arrives at the Service's port, eBPF code intercepts
the traffic and transparently forwards it to Envoy (using the TPROXY kernel facility).
```

It also explicitly states that the **source IP is preserved** when traffic is forwarded to Envoy:

```rst
In *both* externalTrafficPolicy cases, traffic will arrive at any node
in the cluster, and be forwarded to Envoy while keeping the source IP intact.
```

---

## 3) Host-network mode datapath

### Diagram
```
External Client
   |
   v
(External LB / routing outside K8s Service model)
   |
   v
Node IP : Gateway Port (host listener)
   |
   v
Envoy listener bound to 0.0.0.0/::
   |
   v
Envoy -> Backend Pod
   |
   v
Backend -> Envoy -> Client
```

### Listener binding in host-network mode
Host-network mode explicitly binds Envoy listeners to **all interfaces**:

```go
if i.Config.HostNetworkConfig.Enabled {
	res = append(res, withHostNetworkPort(m, i.Config.IPConfig.IPv4Enabled, i.Config.IPConfig.IPv6Enabled))
}
```

```go
bindAddresses := []string{}
if ipv4Enabled {
	bindAddresses = append(bindAddresses, "0.0.0.0")
}
if ipv6Enabled {
	bindAddresses = append(bindAddresses, "::")
}
```

---

## 4) Why a dedicated IP is required for Envoy/Gateway

### Explicit requirement in config validation
The agent config enforces that Envoy/Gateway requires the agent to create a dedicated IP. This is why delegated IPAM is incompatible with Envoy config:

```go
// envoy config (Ingress, Gateway API, ...) require cilium-agent to create an IP address
// specifically for differentiating envoy traffic, which is not possible
// with delegated IPAM.
if c.EnableEnvoyConfig {
	return fmt.Errorf("--%s must be disabled with --%s=%s", EnableEnvoyConfig, IPAM, ipamOption.IPAMDelegatedPlugin)
}
```

### The routing-table reason (not just “marks”)
Proxy routing uses **policy routing** and installs **local/next-hop routes** anchored on the **Cilium internal IP**. Marks select the table, but the table still needs a concrete IP target:

```go
fromProxyToCiliumHostRoute4 := route.Route{
	Table: linux_defaults.RouteTableFromProxy,
	Prefix: net.IPNet{
		IP:   ipv4,
		Mask: net.CIDRMask(32, 32),
	},
	Device: device,
	Type:   route.RTN_LOCAL,
}

fromProxyDefaultRoute4 := route.Route{
	Table:   linux_defaults.RouteTableFromProxy,
	Nexthop: &ipv4,
	Device:  device,
}
```

**Takeaway:** the dedicated IP is required because the routing table needs an **L3 next-hop/local route target** for proxy-originated traffic. This is a functional requirement of the datapath, not just an identifier.

---

## 5) Why backend pods don’t reply directly to the external client

For proxied HTTP/HTTPS, Envoy **terminates the client connection** and opens a **new upstream TCP connection** to the backend. This is why the backend’s TCP peer is Envoy (often node IP), and replies go back to Envoy rather than directly to the client. The docs make this explicit for TLS passthrough:

```rst
Because it's a new TCP stream, as far as the backends are concerned,
the source IP is Envoy (which is often the Node IP, depending on your Cilium config).
```

This aligns with the L7 proxy model where client identity is forwarded via headers (X-Forwarded-For / X-Envoy-External-Address), while the upstream TCP peer is Envoy.

---

## 6) Pros/cons and limitations

### Default (non-host-network) mode
**Pros**
- Automatic **external LB creation** via Service type `LoadBalancer`.
- Standard Kubernetes workflow for managed clouds.
- eBPF+TPROXY delivery to Envoy with **source IP preserved** to Envoy.

**Limitations / considerations**
- Requires a cluster environment that **supports `LoadBalancer` Services**.

### Host-network mode
**Pros**
- Useful when **LoadBalancer Services are unavailable** or when external LB/routing is managed outside K8s.
- Envoy binds directly to host interfaces (`0.0.0.0` / `::`).

**Limitations / considerations**
- **No Service-based external LB** is created (Service type is ClusterIP).
- Ports must be **unique across nodes** (port conflicts are possible).
- Binding to **privileged ports** requires extra capabilities (`NET_BIND_SERVICE`).

---

## 7) Recommended mode for typical managed K8s (e.g., AKS)

Per the documented intent, if the environment supports **LoadBalancer Services**, the default mode is the natural fit:
- Cilium creates a `LoadBalancer` Service per Gateway.
- The cloud provider’s LB controller provisions the external load balancer.

Host-network mode is intended for environments where **`LoadBalancer` Services are unavailable** or when external LB/routing is managed outside the Kubernetes Service model.

---

## 8) End-to-end summary (side-by-side)

| Aspect | Default (non-host-network) | Host-network |
|---|---|---|
| Service type | LoadBalancer | ClusterIP |
| External LB | Created by cloud LB controller from Service | Not created by Service; must be external |
| Listener binding | Not explicitly bound to 0.0.0.0/:: in translator | Explicitly bound to 0.0.0.0/:: |
| Traffic delivery | LB → Service port → eBPF+TPROXY → Envoy | External routing → Node IP/Port → Envoy |
| Dedicated IP requirement | Required (routing table next-hop/local route) | Still required (same routing table requirement) |

---

## 9) Source references (expanded excerpts)

### Gateway Service type selection
```go
// If hostNetwork is enabled, it returns ServiceTypeClusterIP. The default value is ServiceTypeLoadBalancer.
func (t *gatewayAPITranslator) toServiceType(params *model.Service) corev1.ServiceType {
	if t.cfg.HostNetworkConfig.Enabled {
		return corev1.ServiceTypeClusterIP
	}
	if params == nil {
		return corev1.ServiceTypeLoadBalancer
	}
	return corev1.ServiceType(params.Type)
}
```

### Host-network mode doc
```rst
* Enabling the Cilium Gateway API host network mode automatically disables the LoadBalancer type Service mode. They are mutually exclusive.
* The listener is exposed on all interfaces (0.0.0.0 for IPv4 and/or :: for IPv6).
```

### Listener binding (host-network)
```go
if i.Config.HostNetworkConfig.Enabled {
	res = append(res, withHostNetworkPort(m, i.Config.IPConfig.IPv4Enabled, i.Config.IPConfig.IPv6Enabled))
}
```

```go
bindAddresses := []string{}
if ipv4Enabled {
	bindAddresses = append(bindAddresses, "0.0.0.0")
}
if ipv6Enabled {
	bindAddresses = append(bindAddresses, "::")
}
```

### TPROXY and Envoy forwarding
```rst
Cilium's Ingress and Gateway API config is exposed with a Loadbalancer or NodePort
service, or optionally can be exposed on the Host network also. But in all of
these cases, when traffic arrives at the Service's port, eBPF code intercepts
the traffic and transparently forwards it to Envoy (using the TPROXY kernel facility).
```

### Source IP preserved when forwarded to Envoy
```rst
In *both* externalTrafficPolicy cases, traffic will arrive at any node
in the cluster, and be forwarded to Envoy while keeping the source IP intact.
```

### Dedicated IP requirement (delegated IPAM restriction)
```go
// envoy config (Ingress, Gateway API, ...) require cilium-agent to create an IP address
// specifically for differentiating envoy traffic, which is not possible
// with delegated IPAM.
if c.EnableEnvoyConfig {
	return fmt.Errorf("--%s must be disabled with --%s=%s", EnableEnvoyConfig, IPAM, ipamOption.IPAMDelegatedPlugin)
}
```

### Proxy routing: local route + next-hop to Cilium internal IP
```go
fromProxyToCiliumHostRoute4 := route.Route{
	Table: linux_defaults.RouteTableFromProxy,
	Prefix: net.IPNet{
		IP:   ipv4,
		Mask: net.CIDRMask(32, 32),
	},
	Device: device,
	Type:   route.RTN_LOCAL,
}

fromProxyDefaultRoute4 := route.Route{
	Table:   linux_defaults.RouteTableFromProxy,
	Nexthop: &ipv4,
	Device:  device,
}
```

### TLS passthrough (backend sees Envoy as source)
```rst
Because it's a new TCP stream, as far as the backends are concerned,
the source IP is Envoy (which is often the Node IP, depending on your Cilium config).
```
