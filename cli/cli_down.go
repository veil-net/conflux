package cli

type Down struct{}

func (cmd *Down) Run() error {
	conflux := NewConflux()
	conflux.Remove()
	return nil
}