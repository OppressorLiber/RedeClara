using System;
using System.Collections.Generic;

namespace RedeClara
{
    public class AdapterInfo
    {
        public string Id { get; set; }
        public string Name { get; set; }
        public string Address { get; set; }
        public int PrefixLength { get; set; }
        public int InterfaceIndex { get; set; }
        public string RangeLabel { get; set; }
        public override string ToString() { return Name + "  ·  " + Address; }
    }
    public class DeviceInfo
    {
        public string Address { get; set; }
        public string HostName { get; set; }
        public bool SmbOpen { get; set; }
        public bool IsLocal { get; set; }
        public string Source { get; set; }
        public string DisplayName { get { return string.IsNullOrWhiteSpace(HostName) ? Address : HostName; } }
        public string Target { get { return IsLocal ? Environment.MachineName : Address; } }
        public string Status { get { return IsLocal ? "Este computador" : (SmbOpen ? "Porta SMB aberta" : "Detectado · SMB sem resposta"); } }
    }
    public class ShareInfo
    {
        public string Name { get; set; }
        public string Remark { get; set; }
        public uint Type { get; set; }
        public bool IsHidden { get { return Name != null && Name.EndsWith("$", StringComparison.Ordinal); } }
        public bool IsDisk { get { return (Type & 255) == 0; } }
    }
    public class ShareResult
    {
        public List<ShareInfo> Shares { get; set; }
        public int ErrorCode { get; set; }
        public string Message { get; set; }
        public ShareResult() { Shares = new List<ShareInfo>(); }
    }
    public class SetupResult
    {
        public bool Success { get; set; }
        public string Message { get; set; }
        public string Details { get; set; }
        public string ReportPath { get; set; }
    }
}
