// Code generated by protoc-gen-gogo. DO NOT EDIT.
// source: akash/cert/v1beta1/query.proto

package types

import (
	context "context"
	fmt "fmt"
	query "github.com/cosmos/cosmos-sdk/types/query"
	_ "github.com/gogo/protobuf/gogoproto"
	grpc1 "github.com/gogo/protobuf/grpc"
	proto "github.com/gogo/protobuf/proto"
	_ "google.golang.org/genproto/googleapis/api/annotations"
	grpc "google.golang.org/grpc"
	codes "google.golang.org/grpc/codes"
	status "google.golang.org/grpc/status"
	io "io"
	math "math"
	math_bits "math/bits"
)

// Reference imports to suppress errors if they are not otherwise used.
var _ = proto.Marshal
var _ = fmt.Errorf
var _ = math.Inf

// This is a compile-time assertion to ensure that this generated file
// is compatible with the proto package it is being compiled against.
// A compilation error at this line likely means your copy of the
// proto package needs to be updated.
const _ = proto.GoGoProtoPackageIsVersion3 // please upgrade the proto package

// QueryDeploymentsRequest is request type for the Query/Deployments RPC method
type QueryCertificatesRequest struct {
	Filter     CertificateFilter  `protobuf:"bytes,1,opt,name=filter,proto3" json:"filter"`
	Pagination *query.PageRequest `protobuf:"bytes,2,opt,name=pagination,proto3" json:"pagination,omitempty"`
}

func (m *QueryCertificatesRequest) Reset()         { *m = QueryCertificatesRequest{} }
func (m *QueryCertificatesRequest) String() string { return proto.CompactTextString(m) }
func (*QueryCertificatesRequest) ProtoMessage()    {}
func (*QueryCertificatesRequest) Descriptor() ([]byte, []int) {
	return fileDescriptor_253641229681779f, []int{0}
}
func (m *QueryCertificatesRequest) XXX_Unmarshal(b []byte) error {
	return m.Unmarshal(b)
}
func (m *QueryCertificatesRequest) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	if deterministic {
		return xxx_messageInfo_QueryCertificatesRequest.Marshal(b, m, deterministic)
	} else {
		b = b[:cap(b)]
		n, err := m.MarshalToSizedBuffer(b)
		if err != nil {
			return nil, err
		}
		return b[:n], nil
	}
}
func (m *QueryCertificatesRequest) XXX_Merge(src proto.Message) {
	xxx_messageInfo_QueryCertificatesRequest.Merge(m, src)
}
func (m *QueryCertificatesRequest) XXX_Size() int {
	return m.Size()
}
func (m *QueryCertificatesRequest) XXX_DiscardUnknown() {
	xxx_messageInfo_QueryCertificatesRequest.DiscardUnknown(m)
}

var xxx_messageInfo_QueryCertificatesRequest proto.InternalMessageInfo

func (m *QueryCertificatesRequest) GetFilter() CertificateFilter {
	if m != nil {
		return m.Filter
	}
	return CertificateFilter{}
}

func (m *QueryCertificatesRequest) GetPagination() *query.PageRequest {
	if m != nil {
		return m.Pagination
	}
	return nil
}

// QueryCertificatesResponse is response type for the Query/Certificates RPC method
type QueryCertificatesResponse struct {
	Certificates Certificates        `protobuf:"bytes,1,rep,name=certificates,proto3,castrepeated=Certificates" json:"certificates"`
	Pagination   *query.PageResponse `protobuf:"bytes,2,opt,name=pagination,proto3" json:"pagination,omitempty"`
}

func (m *QueryCertificatesResponse) Reset()         { *m = QueryCertificatesResponse{} }
func (m *QueryCertificatesResponse) String() string { return proto.CompactTextString(m) }
func (*QueryCertificatesResponse) ProtoMessage()    {}
func (*QueryCertificatesResponse) Descriptor() ([]byte, []int) {
	return fileDescriptor_253641229681779f, []int{1}
}
func (m *QueryCertificatesResponse) XXX_Unmarshal(b []byte) error {
	return m.Unmarshal(b)
}
func (m *QueryCertificatesResponse) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	if deterministic {
		return xxx_messageInfo_QueryCertificatesResponse.Marshal(b, m, deterministic)
	} else {
		b = b[:cap(b)]
		n, err := m.MarshalToSizedBuffer(b)
		if err != nil {
			return nil, err
		}
		return b[:n], nil
	}
}
func (m *QueryCertificatesResponse) XXX_Merge(src proto.Message) {
	xxx_messageInfo_QueryCertificatesResponse.Merge(m, src)
}
func (m *QueryCertificatesResponse) XXX_Size() int {
	return m.Size()
}
func (m *QueryCertificatesResponse) XXX_DiscardUnknown() {
	xxx_messageInfo_QueryCertificatesResponse.DiscardUnknown(m)
}

var xxx_messageInfo_QueryCertificatesResponse proto.InternalMessageInfo

func (m *QueryCertificatesResponse) GetCertificates() Certificates {
	if m != nil {
		return m.Certificates
	}
	return nil
}

func (m *QueryCertificatesResponse) GetPagination() *query.PageResponse {
	if m != nil {
		return m.Pagination
	}
	return nil
}

func init() {
	proto.RegisterType((*QueryCertificatesRequest)(nil), "akash.cert.v1beta1.QueryCertificatesRequest")
	proto.RegisterType((*QueryCertificatesResponse)(nil), "akash.cert.v1beta1.QueryCertificatesResponse")
}

func init() { proto.RegisterFile("akash/cert/v1beta1/query.proto", fileDescriptor_253641229681779f) }

var fileDescriptor_253641229681779f = []byte{
	// 396 bytes of a gzipped FileDescriptorProto
	0x1f, 0x8b, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0xff, 0x8c, 0x92, 0x31, 0x6f, 0xda, 0x40,
	0x1c, 0xc5, 0x7d, 0xb4, 0x65, 0x38, 0x98, 0x4e, 0x0c, 0x2e, 0x6a, 0x0d, 0x42, 0xa5, 0xa0, 0xaa,
	0xdc, 0x09, 0xba, 0x77, 0x00, 0x89, 0xae, 0x0d, 0x5b, 0xb2, 0x9d, 0xad, 0xc3, 0x9c, 0x30, 0x3e,
	0xe3, 0x3b, 0x50, 0x58, 0xf3, 0x09, 0x22, 0x65, 0xcb, 0x1c, 0x29, 0x52, 0xbe, 0x44, 0x56, 0x46,
	0xa4, 0x2c, 0x99, 0x92, 0x08, 0xf2, 0x41, 0x22, 0x9f, 0x4d, 0x62, 0x14, 0x23, 0xb2, 0x59, 0x7e,
	0xef, 0xff, 0xfe, 0xbf, 0x67, 0xff, 0xa1, 0x45, 0xc7, 0x54, 0x8e, 0x88, 0xc3, 0x42, 0x45, 0xe6,
	0x6d, 0x9b, 0x29, 0xda, 0x26, 0xd3, 0x19, 0x0b, 0x17, 0x38, 0x08, 0x85, 0x12, 0x08, 0x69, 0x1d,
	0x47, 0x3a, 0x4e, 0xf4, 0x72, 0xc9, 0x15, 0xae, 0xd0, 0x32, 0x89, 0x9e, 0x62, 0x67, 0xf9, 0x9b,
	0x2b, 0x84, 0xeb, 0x31, 0x42, 0x03, 0x4e, 0xa8, 0xef, 0x0b, 0x45, 0x15, 0x17, 0xbe, 0x4c, 0xd4,
	0x5f, 0x8e, 0x90, 0x13, 0x21, 0x89, 0x4d, 0x25, 0x8b, 0x17, 0xbc, 0xae, 0x0b, 0xa8, 0xcb, 0x7d,
	0x6d, 0x4e, 0xbc, 0xdf, 0x33, 0x98, 0x34, 0x80, 0x96, 0x6b, 0xd7, 0x00, 0x9a, 0x47, 0x51, 0x42,
	0x8f, 0x85, 0x8a, 0x0f, 0xb9, 0x43, 0x15, 0x93, 0x03, 0x36, 0x9d, 0x31, 0xa9, 0x50, 0x0f, 0xe6,
	0x87, 0xdc, 0x53, 0x2c, 0x34, 0x41, 0x15, 0x34, 0x0b, 0x9d, 0x3a, 0x7e, 0x5f, 0x00, 0xa7, 0x06,
	0xfb, 0xda, 0xdc, 0xfd, 0xbc, 0x7c, 0xa8, 0x18, 0x83, 0x64, 0x14, 0xf5, 0x21, 0x7c, 0x83, 0x32,
	0x73, 0x3a, 0xe8, 0x27, 0x8e, 0x1b, 0xe0, 0xa8, 0x01, 0x8e, 0x3f, 0xd1, 0x36, 0xef, 0x3f, 0x75,
	0x59, 0x02, 0x30, 0x48, 0x4d, 0xd6, 0x6e, 0x01, 0xfc, 0x9a, 0x41, 0x2a, 0x03, 0xe1, 0x4b, 0x86,
	0x8e, 0x61, 0xd1, 0x49, 0xbd, 0x37, 0x41, 0xf5, 0x53, 0xb3, 0xd0, 0xa9, 0x1c, 0x00, 0xee, 0x96,
	0x22, 0xd4, 0x9b, 0xc7, 0x4a, 0x71, 0x27, 0x74, 0x27, 0x0a, 0xfd, 0xcb, 0x28, 0xd0, 0x38, 0x58,
	0x20, 0xe6, 0x4a, 0x37, 0xe8, 0x5c, 0x01, 0xf8, 0x45, 0x37, 0x40, 0x97, 0x00, 0xee, 0x6c, 0x44,
	0xbf, 0xb3, 0x40, 0xf7, 0xfd, 0x97, 0x72, 0xeb, 0x83, 0xee, 0x98, 0xa1, 0xd6, 0x3a, 0xbb, 0x7b,
	0xbe, 0xc8, 0x35, 0x50, 0x9d, 0xec, 0xb9, 0x85, 0xed, 0x04, 0xf1, 0xb8, 0x54, 0xdd, 0xbf, 0xcb,
	0xb5, 0x05, 0x56, 0x6b, 0x0b, 0x3c, 0xad, 0x2d, 0x70, 0xbe, 0xb1, 0x8c, 0xd5, 0xc6, 0x32, 0xee,
	0x37, 0x96, 0x71, 0xf2, 0xc3, 0xe5, 0x6a, 0x34, 0xb3, 0xb1, 0x23, 0x26, 0x44, 0xcc, 0x43, 0xc7,
	0x1b, 0x27, 0x89, 0xa7, 0x71, 0xa6, 0x5a, 0x04, 0x4c, 0xda, 0x79, 0x7d, 0x59, 0x7f, 0x5e, 0x02,
	0x00, 0x00, 0xff, 0xff, 0xa1, 0xde, 0x5b, 0x79, 0x0e, 0x03, 0x00, 0x00,
}

// Reference imports to suppress errors if they are not otherwise used.
var _ context.Context
var _ grpc.ClientConn

// This is a compile-time assertion to ensure that this generated file
// is compatible with the grpc package it is being compiled against.
const _ = grpc.SupportPackageIsVersion4

// QueryClient is the client API for Query service.
//
// For semantics around ctx use and closing/ending streaming RPCs, please refer to https://godoc.org/google.golang.org/grpc#ClientConn.NewStream.
type QueryClient interface {
	Certificates(ctx context.Context, in *QueryCertificatesRequest, opts ...grpc.CallOption) (*QueryCertificatesResponse, error)
}

type queryClient struct {
	cc grpc1.ClientConn
}

func NewQueryClient(cc grpc1.ClientConn) QueryClient {
	return &queryClient{cc}
}

func (c *queryClient) Certificates(ctx context.Context, in *QueryCertificatesRequest, opts ...grpc.CallOption) (*QueryCertificatesResponse, error) {
	out := new(QueryCertificatesResponse)
	err := c.cc.Invoke(ctx, "/akash.cert.v1beta1.Query/Certificates", in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

// QueryServer is the server API for Query service.
type QueryServer interface {
	Certificates(context.Context, *QueryCertificatesRequest) (*QueryCertificatesResponse, error)
}

// UnimplementedQueryServer can be embedded to have forward compatible implementations.
type UnimplementedQueryServer struct {
}

func (*UnimplementedQueryServer) Certificates(ctx context.Context, req *QueryCertificatesRequest) (*QueryCertificatesResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method Certificates not implemented")
}

func RegisterQueryServer(s grpc1.Server, srv QueryServer) {
	s.RegisterService(&_Query_serviceDesc, srv)
}

func _Query_Certificates_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(QueryCertificatesRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(QueryServer).Certificates(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/akash.cert.v1beta1.Query/Certificates",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(QueryServer).Certificates(ctx, req.(*QueryCertificatesRequest))
	}
	return interceptor(ctx, in, info, handler)
}

var _Query_serviceDesc = grpc.ServiceDesc{
	ServiceName: "akash.cert.v1beta1.Query",
	HandlerType: (*QueryServer)(nil),
	Methods: []grpc.MethodDesc{
		{
			MethodName: "Certificates",
			Handler:    _Query_Certificates_Handler,
		},
	},
	Streams:  []grpc.StreamDesc{},
	Metadata: "akash/cert/v1beta1/query.proto",
}

func (m *QueryCertificatesRequest) Marshal() (dAtA []byte, err error) {
	size := m.Size()
	dAtA = make([]byte, size)
	n, err := m.MarshalToSizedBuffer(dAtA[:size])
	if err != nil {
		return nil, err
	}
	return dAtA[:n], nil
}

func (m *QueryCertificatesRequest) MarshalTo(dAtA []byte) (int, error) {
	size := m.Size()
	return m.MarshalToSizedBuffer(dAtA[:size])
}

func (m *QueryCertificatesRequest) MarshalToSizedBuffer(dAtA []byte) (int, error) {
	i := len(dAtA)
	_ = i
	var l int
	_ = l
	if m.Pagination != nil {
		{
			size, err := m.Pagination.MarshalToSizedBuffer(dAtA[:i])
			if err != nil {
				return 0, err
			}
			i -= size
			i = encodeVarintQuery(dAtA, i, uint64(size))
		}
		i--
		dAtA[i] = 0x12
	}
	{
		size, err := m.Filter.MarshalToSizedBuffer(dAtA[:i])
		if err != nil {
			return 0, err
		}
		i -= size
		i = encodeVarintQuery(dAtA, i, uint64(size))
	}
	i--
	dAtA[i] = 0xa
	return len(dAtA) - i, nil
}

func (m *QueryCertificatesResponse) Marshal() (dAtA []byte, err error) {
	size := m.Size()
	dAtA = make([]byte, size)
	n, err := m.MarshalToSizedBuffer(dAtA[:size])
	if err != nil {
		return nil, err
	}
	return dAtA[:n], nil
}

func (m *QueryCertificatesResponse) MarshalTo(dAtA []byte) (int, error) {
	size := m.Size()
	return m.MarshalToSizedBuffer(dAtA[:size])
}

func (m *QueryCertificatesResponse) MarshalToSizedBuffer(dAtA []byte) (int, error) {
	i := len(dAtA)
	_ = i
	var l int
	_ = l
	if m.Pagination != nil {
		{
			size, err := m.Pagination.MarshalToSizedBuffer(dAtA[:i])
			if err != nil {
				return 0, err
			}
			i -= size
			i = encodeVarintQuery(dAtA, i, uint64(size))
		}
		i--
		dAtA[i] = 0x12
	}
	if len(m.Certificates) > 0 {
		for iNdEx := len(m.Certificates) - 1; iNdEx >= 0; iNdEx-- {
			{
				size, err := m.Certificates[iNdEx].MarshalToSizedBuffer(dAtA[:i])
				if err != nil {
					return 0, err
				}
				i -= size
				i = encodeVarintQuery(dAtA, i, uint64(size))
			}
			i--
			dAtA[i] = 0xa
		}
	}
	return len(dAtA) - i, nil
}

func encodeVarintQuery(dAtA []byte, offset int, v uint64) int {
	offset -= sovQuery(v)
	base := offset
	for v >= 1<<7 {
		dAtA[offset] = uint8(v&0x7f | 0x80)
		v >>= 7
		offset++
	}
	dAtA[offset] = uint8(v)
	return base
}
func (m *QueryCertificatesRequest) Size() (n int) {
	if m == nil {
		return 0
	}
	var l int
	_ = l
	l = m.Filter.Size()
	n += 1 + l + sovQuery(uint64(l))
	if m.Pagination != nil {
		l = m.Pagination.Size()
		n += 1 + l + sovQuery(uint64(l))
	}
	return n
}

func (m *QueryCertificatesResponse) Size() (n int) {
	if m == nil {
		return 0
	}
	var l int
	_ = l
	if len(m.Certificates) > 0 {
		for _, e := range m.Certificates {
			l = e.Size()
			n += 1 + l + sovQuery(uint64(l))
		}
	}
	if m.Pagination != nil {
		l = m.Pagination.Size()
		n += 1 + l + sovQuery(uint64(l))
	}
	return n
}

func sovQuery(x uint64) (n int) {
	return (math_bits.Len64(x|1) + 6) / 7
}
func sozQuery(x uint64) (n int) {
	return sovQuery(uint64((x << 1) ^ uint64((int64(x) >> 63))))
}
func (m *QueryCertificatesRequest) Unmarshal(dAtA []byte) error {
	l := len(dAtA)
	iNdEx := 0
	for iNdEx < l {
		preIndex := iNdEx
		var wire uint64
		for shift := uint(0); ; shift += 7 {
			if shift >= 64 {
				return ErrIntOverflowQuery
			}
			if iNdEx >= l {
				return io.ErrUnexpectedEOF
			}
			b := dAtA[iNdEx]
			iNdEx++
			wire |= uint64(b&0x7F) << shift
			if b < 0x80 {
				break
			}
		}
		fieldNum := int32(wire >> 3)
		wireType := int(wire & 0x7)
		if wireType == 4 {
			return fmt.Errorf("proto: QueryCertificatesRequest: wiretype end group for non-group")
		}
		if fieldNum <= 0 {
			return fmt.Errorf("proto: QueryCertificatesRequest: illegal tag %d (wire type %d)", fieldNum, wire)
		}
		switch fieldNum {
		case 1:
			if wireType != 2 {
				return fmt.Errorf("proto: wrong wireType = %d for field Filter", wireType)
			}
			var msglen int
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return ErrIntOverflowQuery
				}
				if iNdEx >= l {
					return io.ErrUnexpectedEOF
				}
				b := dAtA[iNdEx]
				iNdEx++
				msglen |= int(b&0x7F) << shift
				if b < 0x80 {
					break
				}
			}
			if msglen < 0 {
				return ErrInvalidLengthQuery
			}
			postIndex := iNdEx + msglen
			if postIndex < 0 {
				return ErrInvalidLengthQuery
			}
			if postIndex > l {
				return io.ErrUnexpectedEOF
			}
			if err := m.Filter.Unmarshal(dAtA[iNdEx:postIndex]); err != nil {
				return err
			}
			iNdEx = postIndex
		case 2:
			if wireType != 2 {
				return fmt.Errorf("proto: wrong wireType = %d for field Pagination", wireType)
			}
			var msglen int
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return ErrIntOverflowQuery
				}
				if iNdEx >= l {
					return io.ErrUnexpectedEOF
				}
				b := dAtA[iNdEx]
				iNdEx++
				msglen |= int(b&0x7F) << shift
				if b < 0x80 {
					break
				}
			}
			if msglen < 0 {
				return ErrInvalidLengthQuery
			}
			postIndex := iNdEx + msglen
			if postIndex < 0 {
				return ErrInvalidLengthQuery
			}
			if postIndex > l {
				return io.ErrUnexpectedEOF
			}
			if m.Pagination == nil {
				m.Pagination = &query.PageRequest{}
			}
			if err := m.Pagination.Unmarshal(dAtA[iNdEx:postIndex]); err != nil {
				return err
			}
			iNdEx = postIndex
		default:
			iNdEx = preIndex
			skippy, err := skipQuery(dAtA[iNdEx:])
			if err != nil {
				return err
			}
			if skippy < 0 {
				return ErrInvalidLengthQuery
			}
			if (iNdEx + skippy) < 0 {
				return ErrInvalidLengthQuery
			}
			if (iNdEx + skippy) > l {
				return io.ErrUnexpectedEOF
			}
			iNdEx += skippy
		}
	}

	if iNdEx > l {
		return io.ErrUnexpectedEOF
	}
	return nil
}
func (m *QueryCertificatesResponse) Unmarshal(dAtA []byte) error {
	l := len(dAtA)
	iNdEx := 0
	for iNdEx < l {
		preIndex := iNdEx
		var wire uint64
		for shift := uint(0); ; shift += 7 {
			if shift >= 64 {
				return ErrIntOverflowQuery
			}
			if iNdEx >= l {
				return io.ErrUnexpectedEOF
			}
			b := dAtA[iNdEx]
			iNdEx++
			wire |= uint64(b&0x7F) << shift
			if b < 0x80 {
				break
			}
		}
		fieldNum := int32(wire >> 3)
		wireType := int(wire & 0x7)
		if wireType == 4 {
			return fmt.Errorf("proto: QueryCertificatesResponse: wiretype end group for non-group")
		}
		if fieldNum <= 0 {
			return fmt.Errorf("proto: QueryCertificatesResponse: illegal tag %d (wire type %d)", fieldNum, wire)
		}
		switch fieldNum {
		case 1:
			if wireType != 2 {
				return fmt.Errorf("proto: wrong wireType = %d for field Certificates", wireType)
			}
			var msglen int
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return ErrIntOverflowQuery
				}
				if iNdEx >= l {
					return io.ErrUnexpectedEOF
				}
				b := dAtA[iNdEx]
				iNdEx++
				msglen |= int(b&0x7F) << shift
				if b < 0x80 {
					break
				}
			}
			if msglen < 0 {
				return ErrInvalidLengthQuery
			}
			postIndex := iNdEx + msglen
			if postIndex < 0 {
				return ErrInvalidLengthQuery
			}
			if postIndex > l {
				return io.ErrUnexpectedEOF
			}
			m.Certificates = append(m.Certificates, Certificate{})
			if err := m.Certificates[len(m.Certificates)-1].Unmarshal(dAtA[iNdEx:postIndex]); err != nil {
				return err
			}
			iNdEx = postIndex
		case 2:
			if wireType != 2 {
				return fmt.Errorf("proto: wrong wireType = %d for field Pagination", wireType)
			}
			var msglen int
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return ErrIntOverflowQuery
				}
				if iNdEx >= l {
					return io.ErrUnexpectedEOF
				}
				b := dAtA[iNdEx]
				iNdEx++
				msglen |= int(b&0x7F) << shift
				if b < 0x80 {
					break
				}
			}
			if msglen < 0 {
				return ErrInvalidLengthQuery
			}
			postIndex := iNdEx + msglen
			if postIndex < 0 {
				return ErrInvalidLengthQuery
			}
			if postIndex > l {
				return io.ErrUnexpectedEOF
			}
			if m.Pagination == nil {
				m.Pagination = &query.PageResponse{}
			}
			if err := m.Pagination.Unmarshal(dAtA[iNdEx:postIndex]); err != nil {
				return err
			}
			iNdEx = postIndex
		default:
			iNdEx = preIndex
			skippy, err := skipQuery(dAtA[iNdEx:])
			if err != nil {
				return err
			}
			if skippy < 0 {
				return ErrInvalidLengthQuery
			}
			if (iNdEx + skippy) < 0 {
				return ErrInvalidLengthQuery
			}
			if (iNdEx + skippy) > l {
				return io.ErrUnexpectedEOF
			}
			iNdEx += skippy
		}
	}

	if iNdEx > l {
		return io.ErrUnexpectedEOF
	}
	return nil
}
func skipQuery(dAtA []byte) (n int, err error) {
	l := len(dAtA)
	iNdEx := 0
	depth := 0
	for iNdEx < l {
		var wire uint64
		for shift := uint(0); ; shift += 7 {
			if shift >= 64 {
				return 0, ErrIntOverflowQuery
			}
			if iNdEx >= l {
				return 0, io.ErrUnexpectedEOF
			}
			b := dAtA[iNdEx]
			iNdEx++
			wire |= (uint64(b) & 0x7F) << shift
			if b < 0x80 {
				break
			}
		}
		wireType := int(wire & 0x7)
		switch wireType {
		case 0:
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return 0, ErrIntOverflowQuery
				}
				if iNdEx >= l {
					return 0, io.ErrUnexpectedEOF
				}
				iNdEx++
				if dAtA[iNdEx-1] < 0x80 {
					break
				}
			}
		case 1:
			iNdEx += 8
		case 2:
			var length int
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return 0, ErrIntOverflowQuery
				}
				if iNdEx >= l {
					return 0, io.ErrUnexpectedEOF
				}
				b := dAtA[iNdEx]
				iNdEx++
				length |= (int(b) & 0x7F) << shift
				if b < 0x80 {
					break
				}
			}
			if length < 0 {
				return 0, ErrInvalidLengthQuery
			}
			iNdEx += length
		case 3:
			depth++
		case 4:
			if depth == 0 {
				return 0, ErrUnexpectedEndOfGroupQuery
			}
			depth--
		case 5:
			iNdEx += 4
		default:
			return 0, fmt.Errorf("proto: illegal wireType %d", wireType)
		}
		if iNdEx < 0 {
			return 0, ErrInvalidLengthQuery
		}
		if depth == 0 {
			return iNdEx, nil
		}
	}
	return 0, io.ErrUnexpectedEOF
}

var (
	ErrInvalidLengthQuery        = fmt.Errorf("proto: negative length found during unmarshaling")
	ErrIntOverflowQuery          = fmt.Errorf("proto: integer overflow")
	ErrUnexpectedEndOfGroupQuery = fmt.Errorf("proto: unexpected end of group")
)
