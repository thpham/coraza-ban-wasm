package main

// =============================================================================
// Mock Implementations for Unit Testing
// =============================================================================

// MockLogger implements Logger interface for testing.
type MockLogger struct {
	DebugMessages []string
	InfoMessages  []string
	WarnMessages  []string
	ErrorMessages []string
}

func NewMockLogger() *MockLogger {
	return &MockLogger{
		DebugMessages: []string{},
		InfoMessages:  []string{},
		WarnMessages:  []string{},
		ErrorMessages: []string{},
	}
}

func (l *MockLogger) Debug(format string, args ...interface{}) {
	l.DebugMessages = append(l.DebugMessages, format)
}

func (l *MockLogger) Info(format string, args ...interface{}) {
	l.InfoMessages = append(l.InfoMessages, format)
}

func (l *MockLogger) Warn(format string, args ...interface{}) {
	l.WarnMessages = append(l.WarnMessages, format)
}

func (l *MockLogger) Error(format string, args ...interface{}) {
	l.ErrorMessages = append(l.ErrorMessages, format)
}

// MockBanStore implements BanStore interface for testing.
type MockBanStore struct {
	Bans       map[string]*BanEntry
	SetBanErr  error
	CheckCalls int
	SetCalls   int
}

func NewMockBanStore() *MockBanStore {
	return &MockBanStore{
		Bans: make(map[string]*BanEntry),
	}
}

func (s *MockBanStore) CheckBan(fingerprint string) (*BanEntry, bool) {
	s.CheckCalls++
	entry, found := s.Bans[fingerprint]
	return entry, found
}

func (s *MockBanStore) SetBan(entry *BanEntry) error {
	s.SetCalls++
	if s.SetBanErr != nil {
		return s.SetBanErr
	}
	s.Bans[entry.Fingerprint] = entry
	return nil
}

func (s *MockBanStore) DeleteBan(fingerprint string) error {
	delete(s.Bans, fingerprint)
	return nil
}

// MockScoreStore implements ScoreStore interface for testing.
type MockScoreStore struct {
	Scores      map[string]*ScoreEntry
	IncrScoreErr error
	IncrCalls    int
}

func NewMockScoreStore() *MockScoreStore {
	return &MockScoreStore{
		Scores: make(map[string]*ScoreEntry),
	}
}

func (s *MockScoreStore) GetScore(fingerprint string) (*ScoreEntry, bool) {
	entry, found := s.Scores[fingerprint]
	return entry, found
}

func (s *MockScoreStore) SetScore(entry *ScoreEntry) error {
	s.Scores[entry.Fingerprint] = entry
	return nil
}

func (s *MockScoreStore) IncrScore(fingerprint string, increment int) (int, error) {
	s.IncrCalls++
	if s.IncrScoreErr != nil {
		return 0, s.IncrScoreErr
	}

	entry, found := s.Scores[fingerprint]
	if !found {
		entry = NewScoreEntry(fingerprint)
		s.Scores[fingerprint] = entry
	}
	entry.Score += increment
	return entry.Score, nil
}

// MockRedisClient implements RedisClient interface for testing.
type MockRedisClient struct {
	Configured     bool
	BannedEntries  map[string]*BanEntry
	Scores         map[string]int
	CheckBanCalls  int
	SetBanCalls    int
	IncrScoreCalls int
}

func NewMockRedisClient(configured bool) *MockRedisClient {
	return &MockRedisClient{
		Configured:    configured,
		BannedEntries: make(map[string]*BanEntry),
		Scores:        make(map[string]int),
	}
}

func (c *MockRedisClient) IsConfigured() bool {
	return c.Configured
}

func (c *MockRedisClient) CheckBanAsync(fingerprint string, callback func(bool, *BanEntry)) {
	c.CheckBanCalls++
	entry, found := c.BannedEntries[fingerprint]
	callback(found, entry)
}

func (c *MockRedisClient) SetBanAsync(entry *BanEntry, callback func(bool)) {
	c.SetBanCalls++
	c.BannedEntries[entry.Fingerprint] = entry
	callback(true)
}

func (c *MockRedisClient) DeleteBanAsync(fingerprint string) {
	delete(c.BannedEntries, fingerprint)
}

func (c *MockRedisClient) IncrScoreAsync(fingerprint string, increment, ttl int, callback func(int, bool)) {
	c.IncrScoreCalls++
	c.Scores[fingerprint] += increment
	callback(c.Scores[fingerprint], true)
}

func (c *MockRedisClient) GetScoreAsync(fingerprint string, callback func(int, bool)) {
	score, found := c.Scores[fingerprint]
	callback(score, found)
}

// MockEventHandler implements EventHandler interface for testing.
type MockEventHandler struct {
	Events []*BanEvent
}

func NewMockEventHandler() *MockEventHandler {
	return &MockEventHandler{
		Events: []*BanEvent{},
	}
}

func (h *MockEventHandler) OnBanEvent(event *BanEvent) {
	h.Events = append(h.Events, event)
}

// =============================================================================
// Compile-Time Interface Verification for Mocks
// =============================================================================

var (
	_ Logger       = (*MockLogger)(nil)
	_ BanStore     = (*MockBanStore)(nil)
	_ ScoreStore   = (*MockScoreStore)(nil)
	_ RedisClient  = (*MockRedisClient)(nil)
	_ EventHandler = (*MockEventHandler)(nil)
)
