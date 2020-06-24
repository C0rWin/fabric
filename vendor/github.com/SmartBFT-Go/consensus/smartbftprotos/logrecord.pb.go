// Code generated by protoc-gen-go. DO NOT EDIT.
// source: orderer/smartbftprotos/logrecord.proto

package smartbftprotos // import "github.com/SmartBFT-Go/consensus/smartbftprotos"

import proto "github.com/golang/protobuf/proto"
import fmt "fmt"
import math "math"

// Reference imports to suppress errors if they are not otherwise used.
var _ = proto.Marshal
var _ = fmt.Errorf
var _ = math.Inf

// This is a compile-time assertion to ensure that this generated file
// is compatible with the proto package it is being compiled against.
// A compilation error at this line likely means your copy of the
// proto package needs to be updated.
const _ = proto.ProtoPackageIsVersion2 // please upgrade the proto package

type LogRecord_Type int32

const (
	LogRecord_ENTRY      LogRecord_Type = 0
	LogRecord_CONTROL    LogRecord_Type = 1
	LogRecord_CRC_ANCHOR LogRecord_Type = 2
)

var LogRecord_Type_name = map[int32]string{
	0: "ENTRY",
	1: "CONTROL",
	2: "CRC_ANCHOR",
}
var LogRecord_Type_value = map[string]int32{
	"ENTRY":      0,
	"CONTROL":    1,
	"CRC_ANCHOR": 2,
}

func (x LogRecord_Type) String() string {
	return proto.EnumName(LogRecord_Type_name, int32(x))
}
func (LogRecord_Type) EnumDescriptor() ([]byte, []int) {
	return fileDescriptor_logrecord_a9b31c857013af85, []int{0, 0}
}

type LogRecord struct {
	Type                 LogRecord_Type `protobuf:"varint,1,opt,name=type,proto3,enum=smartbftprotos.LogRecord_Type" json:"type,omitempty"`
	TruncateTo           bool           `protobuf:"varint,2,opt,name=truncate_to,json=truncateTo,proto3" json:"truncate_to,omitempty"`
	Data                 []byte         `protobuf:"bytes,3,opt,name=data,proto3" json:"data,omitempty"`
	XXX_NoUnkeyedLiteral struct{}       `json:"-"`
	XXX_unrecognized     []byte         `json:"-"`
	XXX_sizecache        int32          `json:"-"`
}

func (m *LogRecord) Reset()         { *m = LogRecord{} }
func (m *LogRecord) String() string { return proto.CompactTextString(m) }
func (*LogRecord) ProtoMessage()    {}
func (*LogRecord) Descriptor() ([]byte, []int) {
	return fileDescriptor_logrecord_a9b31c857013af85, []int{0}
}
func (m *LogRecord) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_LogRecord.Unmarshal(m, b)
}
func (m *LogRecord) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_LogRecord.Marshal(b, m, deterministic)
}
func (dst *LogRecord) XXX_Merge(src proto.Message) {
	xxx_messageInfo_LogRecord.Merge(dst, src)
}
func (m *LogRecord) XXX_Size() int {
	return xxx_messageInfo_LogRecord.Size(m)
}
func (m *LogRecord) XXX_DiscardUnknown() {
	xxx_messageInfo_LogRecord.DiscardUnknown(m)
}

var xxx_messageInfo_LogRecord proto.InternalMessageInfo

func (m *LogRecord) GetType() LogRecord_Type {
	if m != nil {
		return m.Type
	}
	return LogRecord_ENTRY
}

func (m *LogRecord) GetTruncateTo() bool {
	if m != nil {
		return m.TruncateTo
	}
	return false
}

func (m *LogRecord) GetData() []byte {
	if m != nil {
		return m.Data
	}
	return nil
}

func init() {
	proto.RegisterType((*LogRecord)(nil), "smartbftprotos.LogRecord")
	proto.RegisterEnum("smartbftprotos.LogRecord_Type", LogRecord_Type_name, LogRecord_Type_value)
}

func init() {
	proto.RegisterFile("orderer/smartbftprotos/logrecord.proto", fileDescriptor_logrecord_a9b31c857013af85)
}

var fileDescriptor_logrecord_a9b31c857013af85 = []byte{
	// 239 bytes of a gzipped FileDescriptorProto
	0x1f, 0x8b, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0xff, 0x6c, 0xd0, 0x4d, 0x4b, 0xf3, 0x40,
	0x10, 0x07, 0xf0, 0x67, 0xfb, 0xc4, 0x97, 0x4e, 0x25, 0x84, 0x3d, 0xe5, 0xa4, 0xa1, 0x07, 0xc9,
	0x69, 0x17, 0xea, 0x51, 0x3c, 0x68, 0x10, 0x3c, 0x94, 0x04, 0x96, 0x5c, 0xf4, 0x52, 0x36, 0xc9,
	0x34, 0x2d, 0xb4, 0x4e, 0x98, 0x4e, 0x0f, 0xf9, 0x3e, 0x7e, 0x50, 0x71, 0x51, 0xa1, 0xe0, 0x69,
	0x86, 0xff, 0xfc, 0x18, 0x98, 0x81, 0x5b, 0xe2, 0x0e, 0x19, 0xd9, 0x1e, 0xf6, 0x9e, 0xa5, 0x59,
	0xcb, 0xc0, 0x24, 0x74, 0xb0, 0x3b, 0xea, 0x19, 0x5b, 0xe2, 0xce, 0x84, 0x40, 0xc7, 0xa7, 0xf3,
	0xf9, 0x87, 0x82, 0xe9, 0x92, 0x7a, 0x17, 0x8c, 0x5e, 0x40, 0x24, 0xe3, 0x80, 0xa9, 0xca, 0x54,
	0x1e, 0x2f, 0xae, 0xcd, 0x29, 0x36, 0xbf, 0xd0, 0xd4, 0xe3, 0x80, 0x2e, 0x58, 0x7d, 0x03, 0x33,
	0xe1, 0xe3, 0x7b, 0xeb, 0x05, 0x57, 0x42, 0xe9, 0x24, 0x53, 0xf9, 0xa5, 0x83, 0x9f, 0xa8, 0x26,
	0xad, 0x21, 0xea, 0xbc, 0xf8, 0xf4, 0x7f, 0xa6, 0xf2, 0x2b, 0x17, 0xfa, 0xb9, 0x81, 0xe8, 0x6b,
	0x85, 0x9e, 0xc2, 0xd9, 0x73, 0x59, 0xbb, 0xd7, 0xe4, 0x9f, 0x9e, 0xc1, 0x45, 0x51, 0x95, 0xb5,
	0xab, 0x96, 0x89, 0xd2, 0x31, 0x40, 0xe1, 0x8a, 0xd5, 0x63, 0x59, 0xbc, 0x54, 0x2e, 0x99, 0x3c,
	0x3d, 0xbc, 0xdd, 0xf7, 0x5b, 0xd9, 0x1c, 0x1b, 0xd3, 0xd2, 0xde, 0x6e, 0xc6, 0x01, 0x79, 0x87,
	0x5d, 0x8f, 0x6c, 0xd7, 0xbe, 0xe1, 0x6d, 0x6b, 0xbf, 0xcf, 0xfd, 0xfb, 0x0b, 0xcd, 0x79, 0xa8,
	0x77, 0x9f, 0x01, 0x00, 0x00, 0xff, 0xff, 0xa7, 0x76, 0x32, 0x90, 0x26, 0x01, 0x00, 0x00,
}