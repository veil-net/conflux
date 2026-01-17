package anchor

type StartAnchorArgs struct {
	GuardianURL string
	VeilURL     string
	VeilPort    int
	AnchorToken string
	Portal      bool
}

type CreateTUNArgs struct {
	Ifname string
	MTU    int
}

type LinkWithFileDescriptorArgs struct {
	FileDescriptor int
}

type AnchorRPCServer struct {
	Impl Anchor
}

func (s *AnchorRPCServer) CreateAnchor(args interface{}, resp *error) error {
	err := s.Impl.CreateAnchor()
	*resp = err
	return nil
}

func (s *AnchorRPCServer) DestroyAnchor(args interface{}, resp *error) error {
	err := s.Impl.DestroyAnchor()
	*resp = err
	return nil
}

func (s *AnchorRPCServer) StartAnchor(args *StartAnchorArgs, resp *error) error {
	err := s.Impl.StartAnchor(args.GuardianURL, args.VeilURL, args.VeilPort, args.AnchorToken, args.Portal)
	*resp = err
	return nil
}

func (s *AnchorRPCServer) StopAnchor(args interface{}, resp *error) error {
	err := s.Impl.StopAnchor()
	*resp = err
	return nil
}

func (s *AnchorRPCServer) CreateTUN(args *CreateTUNArgs, resp *error) error {
	err := s.Impl.CreateTUN(args.Ifname, args.MTU)
	*resp = err
	return nil
}

func (s *AnchorRPCServer) DestroyTUN(args interface{}, resp *error) error {
	err := s.Impl.DestroyTUN()
	*resp = err
	return nil
}

func (s *AnchorRPCServer) LinkWithTUN(args interface{}, resp *error) error {
	err := s.Impl.LinkWithTUN()
	*resp = err
	return nil
}

func (s *AnchorRPCServer) LinkWithFileDescriptor(args *LinkWithFileDescriptorArgs, resp *error) error {
	err := s.Impl.LinkWithFileDescriptor(args.FileDescriptor)
	*resp = err
	return nil
}

func (s *AnchorRPCServer) GetID(args interface{}, resp *string) error {
	id, err := s.Impl.GetID()
	*resp = id
	return err
}