"""Production-platform layer: security, audit, observability, streaming, interop.

``security``    password hashing, JWT issuance/verification, role-based access.
``audit``       append-only audit trail of operator and system actions.
``metrics``     Prometheus metrics for detection, mitigation and the API.
``interop``     STIX 2.1 / CEF alert export with MITRE ATT&CK mapping.
``bus``         message bus abstraction (in-memory, Redis Streams).
``ipfix``       RFC 7011 IPFIX encoder/decoder for NetShield flow records.
``pipeline``    collector -> features -> inference -> policy streaming services.
``onnx_export`` export detectors to ONNX and serve them with ONNX Runtime.
``timeseries``  TimescaleDB schema and writer for window metrics.
"""
