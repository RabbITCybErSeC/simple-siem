package auth

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/RabbITCybErSeC/simple-siem/internal/audit"
	"gorm.io/gorm"
)

const testActorSessionID = "0190f8dc-6f43-7f0a-8b2f-9c8c0a2d3e4f"

func testActorFor(user User) Actor {
	return Actor{
		UserID:      user.ID,
		SessionID:   testActorSessionID,
		Email:       user.Email,
		DisplayName: user.DisplayName,
		Roles:       []string{RoleAdmin},
	}
}

func stringPointer(value string) *string {
	return &value
}

func createUser(t *testing.T, service *Service, actor Actor, request CreateUserRequest) UserWithRoles {
	t.Helper()
	created, err := service.CreateUser(context.Background(), actor, testClient(), request)
	if err != nil {
		t.Fatalf("CreateUser(%q): %v", request.Email, err)
	}
	return created
}

func TestListUsers(t *testing.T) {
	test := newTestService(t)
	admin := test.createAdmin(t, testEmail)
	actor := testActorFor(admin)
	alice := createUser(t, test.service, actor, CreateUserRequest{
		Email: "alice@example.com", DisplayName: "Alice", Roles: []string{"ANALYST"},
	})
	bob := createUser(t, test.service, actor, CreateUserRequest{
		Email: "bob@example.com", DisplayName: "Bob", Roles: []string{"READ_ONLY", "ANALYST"},
	})
	carol := createUser(t, test.service, actor, CreateUserRequest{
		Email: "carol@example.com", DisplayName: "Carol",
	})
	if err := test.database.Exec(
		"UPDATE users SET status = 'DISABLED' WHERE id = ?", bob.User.ID,
	).Error; err != nil {
		t.Fatalf("disable Bob: %v", err)
	}

	all, total, err := test.service.ListUsers(context.Background(), UserFilter{Page: 1, PageSize: 10})
	if err != nil {
		t.Fatalf("ListUsers: %v", err)
	}
	if total != 4 {
		t.Errorf("ListUsers total = %d, want 4", total)
	}
	if len(all) != 4 {
		t.Fatalf("ListUsers returned %d users, want 4", len(all))
	}
	for index := 1; index < len(all); index++ {
		previous, current := all[index-1].User, all[index].User
		if current.CreatedAt.Before(previous.CreatedAt) ||
			(current.CreatedAt.Equal(previous.CreatedAt) && current.ID < previous.ID) {
			t.Errorf("ListUsers order is not created_at,id: %v then %v", previous.CreatedAt, current.CreatedAt)
		}
	}

	firstPage, total, err := test.service.ListUsers(context.Background(), UserFilter{Page: 1, PageSize: 2})
	if err != nil {
		t.Fatalf("ListUsers page 1: %v", err)
	}
	if total != 4 || len(firstPage) != 2 {
		t.Errorf("ListUsers page 1 = %d users of %d, want 2 of 4", len(firstPage), total)
	}
	secondPage, _, err := test.service.ListUsers(context.Background(), UserFilter{Page: 2, PageSize: 2})
	if err != nil {
		t.Fatalf("ListUsers page 2: %v", err)
	}
	if len(secondPage) != 2 {
		t.Errorf("ListUsers page 2 returned %d users, want 2", len(secondPage))
	}
	if firstPage[0].User.ID == secondPage[0].User.ID {
		t.Error("ListUsers page 1 and page 2 overlap")
	}
	thirdPage, _, err := test.service.ListUsers(context.Background(), UserFilter{Page: 3, PageSize: 2})
	if err != nil {
		t.Fatalf("ListUsers page 3: %v", err)
	}
	if len(thirdPage) != 0 {
		t.Errorf("ListUsers page 3 returned %d users, want 0", len(thirdPage))
	}

	invited, total, err := test.service.ListUsers(context.Background(), UserFilter{Status: "INVITED", Page: 1, PageSize: 10})
	if err != nil {
		t.Fatalf("ListUsers INVITED: %v", err)
	}
	if total != 2 || len(invited) != 2 {
		t.Errorf("ListUsers INVITED = %d users of %d, want 2 of 2", len(invited), total)
	}
	for _, user := range invited {
		if user.User.ID != alice.User.ID && user.User.ID != carol.User.ID {
			t.Errorf("ListUsers INVITED contains %q, want only Alice and Carol", user.User.Email)
		}
	}

	disabled, total, err := test.service.ListUsers(context.Background(), UserFilter{Status: "DISABLED", Page: 1, PageSize: 10})
	if err != nil {
		t.Fatalf("ListUsers DISABLED: %v", err)
	}
	if total != 1 || len(disabled) != 1 || disabled[0].User.ID != bob.User.ID {
		t.Errorf("ListUsers DISABLED = %+v, want only Bob", disabled)
	}

	active, total, err := test.service.ListUsers(context.Background(), UserFilter{Status: "ACTIVE", Page: 1, PageSize: 10})
	if err != nil {
		t.Fatalf("ListUsers ACTIVE: %v", err)
	}
	if total != 1 || len(active) != 1 || active[0].User.ID != admin.ID {
		t.Errorf("ListUsers ACTIVE = %+v, want only the admin", active)
	}

	if _, _, err := test.service.ListUsers(context.Background(), UserFilter{Status: "active"}); !errors.Is(err, ErrInvalidStatus) {
		t.Errorf("ListUsers with a lowercase status = %v, want ErrInvalidStatus", err)
	}

	if _, _, err := test.service.ListUsers(context.Background(), UserFilter{Status: "SERVICE"}); !errors.Is(err, ErrInvalidStatus) {
		t.Errorf("ListUsers with status SERVICE = %v, want ErrInvalidStatus", err)
	}

	if _, _, err := test.service.ListUsers(context.Background(), UserFilter{Page: 100001, PageSize: 10}); !errors.Is(err, audit.ErrInvalidPage) {
		t.Errorf("ListUsers with page 100001 = %v, want audit.ErrInvalidPage", err)
	}
	if _, _, err := test.service.ListUsers(context.Background(), UserFilter{Page: 0, PageSize: 10}); !errors.Is(err, audit.ErrInvalidPage) {
		t.Errorf("ListUsers with page 0 = %v, want audit.ErrInvalidPage", err)
	}
}

func TestListUsersRoles(t *testing.T) {
	test := newTestService(t)
	admin := test.createAdmin(t, testEmail)
	actor := testActorFor(admin)
	created := createUser(t, test.service, actor, CreateUserRequest{
		Email: "bob@example.com", DisplayName: "Bob", Roles: []string{"READ_ONLY", "ANALYST"},
	})

	users, _, err := test.service.ListUsers(context.Background(), UserFilter{Status: "INVITED", Page: 1})
	if err != nil {
		t.Fatalf("ListUsers: %v", err)
	}
	if len(users) != 1 {
		t.Fatalf("ListUsers returned %d users, want 1", len(users))
	}
	got := users[0]
	if got.User.ID != created.User.ID {
		t.Errorf("ListUsers user = %q, want %q", got.User.ID, created.User.ID)
	}
	if len(got.Roles) != 2 || got.Roles[0] != "ANALYST" || got.Roles[1] != "READ_ONLY" {
		t.Errorf("ListUsers roles = %v, want [ANALYST READ_ONLY]", got.Roles)
	}

	empty, total, err := test.service.ListUsers(context.Background(), UserFilter{Status: "DISABLED", Page: 1})
	if err != nil {
		t.Fatalf("ListUsers DISABLED: %v", err)
	}
	if total != 0 || empty == nil || len(empty) != 0 {
		t.Errorf("ListUsers DISABLED = %v of %d, want an empty list", empty, total)
	}
}

// setUserStatus moves a user to another status without the service, so tests
// of reads and single writes do not depend on the other transitions.
func setUserStatus(t *testing.T, db *gorm.DB, userID, status string) {
	t.Helper()
	if err := db.Exec("UPDATE users SET status = ? WHERE id = ?", status, userID).Error; err != nil {
		t.Fatalf("set user %q status to %s: %v", userID, status, err)
	}
}

func TestDirectoryByPrefix(t *testing.T) {
	test := newTestService(t)
	admin := test.createAdmin(t, testEmail)
	actor := testActorFor(admin)
	alice := createUser(t, test.service, actor, CreateUserRequest{
		Email: "alice@example.com", DisplayName: "Alice Analyst", Roles: []string{"ANALYST"},
	})
	alan := createUser(t, test.service, actor, CreateUserRequest{
		Email: "alan@example.com", DisplayName: "Alan Admin", Roles: []string{"ANALYST"},
	})
	alfred := createUser(t, test.service, actor, CreateUserRequest{
		Email: "alfred@example.com", DisplayName: "Alfred Gone", Roles: []string{"ANALYST"},
	})
	setUserStatus(t, test.database, alice.User.ID, StatusActive)
	setUserStatus(t, test.database, alan.User.ID, StatusActive)
	setUserStatus(t, test.database, alfred.User.ID, StatusDisabled)

	entries, err := test.service.Directory(context.Background(), DirectoryFilter{Query: "al"})
	if err != nil {
		t.Fatalf("Directory: %v", err)
	}
	if len(entries) != 2 {
		t.Fatalf("Directory returned %d entries, want only Alan and Alice", len(entries))
	}
	if entries[0].ID != alan.User.ID || entries[0].DisplayName != "Alan Admin" || entries[0].Status != StatusActive {
		t.Errorf("Directory entry 0 = %+v, want Alan Admin ACTIVE", entries[0])
	}
	if entries[1].ID != alice.User.ID || entries[1].DisplayName != "Alice Analyst" || entries[1].Status != StatusActive {
		t.Errorf("Directory entry 1 = %+v, want Alice Analyst ACTIVE", entries[1])
	}

	for _, query := range []string{"AL", " al "} {
		matches, err := test.service.Directory(context.Background(), DirectoryFilter{Query: query})
		if err != nil {
			t.Fatalf("Directory(%q): %v", query, err)
		}
		if len(matches) != 2 || matches[0].ID != alan.User.ID || matches[1].ID != alice.User.ID {
			t.Errorf("Directory(%q) = %+v, want the same two active users", query, matches)
		}
	}

	none, err := test.service.Directory(context.Background(), DirectoryFilter{Query: "zz"})
	if err != nil {
		t.Fatalf("Directory with no matches: %v", err)
	}
	if none == nil || len(none) != 0 {
		t.Errorf("Directory with no matches = %v, want an empty list", none)
	}
}

func TestDirectoryWildcardsAreLiteral(t *testing.T) {
	test := newTestService(t)
	admin := test.createAdmin(t, testEmail)
	actor := testActorFor(admin)
	percent := createUser(t, test.service, actor, CreateUserRequest{
		Email: "percent@example.com", DisplayName: "%Percent",
	})
	under := createUser(t, test.service, actor, CreateUserRequest{
		Email: "under@example.com", DisplayName: "_Under",
	})
	createUser(t, test.service, actor, CreateUserRequest{
		Email: "alice@example.com", DisplayName: "Alice",
	})
	setUserStatus(t, test.database, percent.User.ID, StatusActive)
	setUserStatus(t, test.database, under.User.ID, StatusActive)

	matches, err := test.service.Directory(context.Background(), DirectoryFilter{Query: "%"})
	if err != nil {
		t.Fatalf("Directory(%%): %v", err)
	}
	if len(matches) != 1 || matches[0].ID != percent.User.ID {
		t.Errorf("Directory(%%) = %+v, want only %%Percent", matches)
	}

	matches, err = test.service.Directory(context.Background(), DirectoryFilter{Query: "_"})
	if err != nil {
		t.Fatalf("Directory(_): %v", err)
	}
	if len(matches) != 1 || matches[0].ID != under.User.ID {
		t.Errorf("Directory(_) = %+v, want only _Under", matches)
	}
}

func TestDirectoryLimit(t *testing.T) {
	test := newTestService(t)
	admin := test.createAdmin(t, testEmail)
	actor := testActorFor(admin)
	for index := 0; index < 25; index++ {
		created := createUser(t, test.service, actor, CreateUserRequest{
			Email:       fmt.Sprintf("user%02d@example.com", index),
			DisplayName: fmt.Sprintf("User %02d", index),
		})
		setUserStatus(t, test.database, created.User.ID, StatusActive)
	}

	entries, err := test.service.Directory(context.Background(), DirectoryFilter{Query: "User"})
	if err != nil {
		t.Fatalf("Directory: %v", err)
	}
	if len(entries) != 20 {
		t.Fatalf("Directory returned %d entries, want the default 20", len(entries))
	}
	if entries[0].DisplayName != "User 00" || entries[19].DisplayName != "User 19" {
		t.Errorf("Directory entries = %q..%q, want User 00..User 19", entries[0].DisplayName, entries[19].DisplayName)
	}

	limited, err := test.service.Directory(context.Background(), DirectoryFilter{Query: "User", Limit: 3})
	if err != nil {
		t.Fatalf("Directory with limit 3: %v", err)
	}
	if len(limited) != 3 {
		t.Fatalf("Directory with limit 3 returned %d entries, want 3", len(limited))
	}
	if limited[0].DisplayName != "User 00" || limited[2].DisplayName != "User 02" {
		t.Errorf("Directory entries = %q..%q, want User 00..User 02", limited[0].DisplayName, limited[2].DisplayName)
	}
}

func TestDirectoryByIDsIncludesAnyStatus(t *testing.T) {
	test := newTestService(t)
	admin := test.createAdmin(t, testEmail)
	actor := testActorFor(admin)
	invited := createUser(t, test.service, actor, CreateUserRequest{
		Email: "bob@example.com", DisplayName: "Bob Invited",
	})
	disabled := createUser(t, test.service, actor, CreateUserRequest{
		Email: "ada@example.com", DisplayName: "Ada Disabled",
	})
	setUserStatus(t, test.database, disabled.User.ID, StatusDisabled)
	createUser(t, test.service, actor, CreateUserRequest{
		Email: "carol@example.com", DisplayName: "Carol Not Asked",
	})

	entries, err := test.service.Directory(context.Background(), DirectoryFilter{
		IDs:   []string{invited.User.ID, disabled.User.ID},
		Limit: 1,
	})
	if err != nil {
		t.Fatalf("Directory by ids: %v", err)
	}
	if len(entries) != 2 {
		t.Fatalf("Directory by ids returned %d entries, want both statuses and no limit", len(entries))
	}
	if entries[0].ID != disabled.User.ID || entries[0].Status != StatusDisabled {
		t.Errorf("Directory entry 0 = %+v, want Ada DISABLED", entries[0])
	}
	if entries[1].ID != invited.User.ID || entries[1].Status != StatusInvited {
		t.Errorf("Directory entry 1 = %+v, want Bob INVITED", entries[1])
	}
}

func TestDirectoryRejectsInvalidFilters(t *testing.T) {
	test := newTestService(t)
	admin := test.createAdmin(t, testEmail)
	tooManyIDs := make([]string, 51)
	for index := range tooManyIDs {
		tooManyIDs[index] = fmt.Sprintf("0190f8dc-6f43-7f0a-8b2f-%012x", index)
	}

	tests := []struct {
		name      string
		filter    DirectoryFilter
		parameter string
	}{
		{"query and ids", DirectoryFilter{Query: "al", IDs: []string{admin.ID}}, "q and ids"},
		{"invalid id", DirectoryFilter{IDs: []string{"not-a-uuid"}}, "ids"},
		{"too many ids", DirectoryFilter{IDs: tooManyIDs}, "ids"},
		{"101-rune query", DirectoryFilter{Query: strings.Repeat("a", 101)}, "q"},
		{"blank query", DirectoryFilter{Query: "   "}, "q"},
		{"limit 51", DirectoryFilter{Limit: 51}, "limit"},
		{"negative limit", DirectoryFilter{Limit: -1}, "limit"},
	}
	for _, testCase := range tests {
		t.Run(testCase.name, func(t *testing.T) {
			entries, err := test.service.Directory(context.Background(), testCase.filter)
			if !errors.Is(err, ErrInvalidDirectoryFilter) {
				t.Fatalf("Directory error = %v, want ErrInvalidDirectoryFilter", err)
			}
			if !strings.Contains(err.Error(), testCase.parameter) {
				t.Errorf("Directory error = %q, want it to name %q", err.Error(), testCase.parameter)
			}
			if entries != nil {
				t.Errorf("Directory returned %v with an invalid filter, want nil", entries)
			}
		})
	}
}

func TestListRoles(t *testing.T) {
	test := newTestService(t)
	roles, err := test.service.ListRoles(context.Background())
	if err != nil {
		t.Fatalf("ListRoles: %v", err)
	}
	names := []string{"ADMIN", "ANALYST", "READ_ONLY", "SECURITY_ENGINEER", "SERVICE"}
	if len(roles) != len(names) {
		t.Fatalf("ListRoles returned %d roles, want %d", len(roles), len(names))
	}
	for index, role := range roles {
		if role.Name != names[index] {
			t.Errorf("role %d = %q, want %q", index, role.Name, names[index])
		}
		if role.Description == "" {
			t.Errorf("role %q has no description", role.Name)
		}
		for position := 1; position < len(role.Permissions); position++ {
			if role.Permissions[position-1] >= role.Permissions[position] {
				t.Errorf("role %q permissions are not sorted: %v", role.Name, role.Permissions)
			}
		}
	}
	if !slices.Contains(roles[0].Permissions, "user:read") {
		t.Errorf("ADMIN permissions = %v, want user:read", roles[0].Permissions)
	}
	if roles[4].Permissions == nil || len(roles[4].Permissions) != 0 {
		t.Errorf("SERVICE permissions = %v, want an empty array", roles[4].Permissions)
	}
}

func TestGetUser(t *testing.T) {
	test := newTestService(t)
	admin := test.createAdmin(t, testEmail)
	actor := testActorFor(admin)
	created := createUser(t, test.service, actor, CreateUserRequest{
		Email: "alice@example.com", DisplayName: "Alice", Roles: []string{"ANALYST"},
	})

	found, err := test.service.GetUser(context.Background(), created.User.ID)
	if err != nil {
		t.Fatalf("GetUser: %v", err)
	}
	if found.User.ID != created.User.ID || found.User.Email != "alice@example.com" || found.User.DisplayName != "Alice" {
		t.Errorf("GetUser = %+v, want %+v", found.User, created.User)
	}
	if found.User.Status != "INVITED" {
		t.Errorf("GetUser status = %q, want INVITED", found.User.Status)
	}
	if len(found.Roles) != 1 || found.Roles[0] != "ANALYST" {
		t.Errorf("GetUser roles = %v, want [ANALYST]", found.Roles)
	}

	_, err = test.service.GetUser(context.Background(), "0190f8dc-6f43-7f0a-8b2f-9c8c0a2d3e4f")
	if !errors.Is(err, ErrUserNotFound) {
		t.Errorf("GetUser(random id) = %v, want ErrUserNotFound", err)
	}
}

func TestCreateUser(t *testing.T) {
	test := newTestService(t)
	admin := test.createAdmin(t, testEmail)
	actor := testActorFor(admin)

	created, err := test.service.CreateUser(
		context.Background(),
		actor,
		testClient(),
		CreateUserRequest{
			Email:       " Alice@Example.com ",
			DisplayName: " Alice ",
			Roles:       []string{"READ_ONLY", "ANALYST", "ANALYST"},
		},
	)
	if err != nil {
		t.Fatalf("CreateUser: %v", err)
	}
	if created.User.ID == "" {
		t.Fatal("CreateUser returned a user without an id")
	}
	if created.User.Email != "alice@example.com" {
		t.Errorf("created email = %q, want alice@example.com", created.User.Email)
	}
	if created.User.DisplayName != "Alice" {
		t.Errorf("created display name = %q, want Alice", created.User.DisplayName)
	}
	if created.User.Status != "INVITED" {
		t.Errorf("created status = %q, want INVITED", created.User.Status)
	}
	if created.User.Version != 1 {
		t.Errorf("created version = %d, want 1", created.User.Version)
	}
	if len(created.Roles) != 2 || created.Roles[0] != "ANALYST" || created.Roles[1] != "READ_ONLY" {
		t.Errorf("created roles = %v, want [ANALYST READ_ONLY]", created.Roles)
	}

	var identities int64
	if err := test.database.Raw(
		"SELECT count(*) FROM user_identities WHERE user_id = ?", created.User.ID,
	).Scan(&identities).Error; err != nil {
		t.Fatalf("count identities: %v", err)
	}
	if identities != 0 {
		t.Errorf("created user has %d identities, want 0", identities)
	}
	var roleCount int64
	if err := test.database.Raw(
		"SELECT count(*) FROM user_roles WHERE user_id = ?", created.User.ID,
	).Scan(&roleCount).Error; err != nil {
		t.Fatalf("count roles: %v", err)
	}
	if roleCount != 2 {
		t.Errorf("created user has %d roles, want 2 (duplicates collapsed)", roleCount)
	}

	events := auditEventsForTarget(t, test.database, created.User.ID)
	if len(events) != 1 {
		t.Fatalf("CreateUser wrote %d audit events, want 1", len(events))
	}
	event := events[0]
	if event.EventName != "simple_siem.user.created" {
		t.Errorf("audit event name = %q, want simple_siem.user.created", event.EventName)
	}
	if event.EventCategory != "USER" || event.EventOutcome != "SUCCESS" {
		t.Errorf("audit event = %s/%s, want USER/SUCCESS", event.EventCategory, event.EventOutcome)
	}
	if event.ActorType != "USER" || event.ActorID == nil || *event.ActorID != admin.ID {
		t.Errorf("audit actor = %s/%v, want USER/%q", event.ActorType, event.ActorID, admin.ID)
	}
	if event.ActorSessionID == nil || *event.ActorSessionID != testActorSessionID {
		t.Errorf("audit actor session = %v, want %q", event.ActorSessionID, testActorSessionID)
	}
	if event.RequestID != "request-1" || event.SourceIP == nil || *event.SourceIP != "192.0.2.7" {
		t.Errorf("audit request/source = %q/%v, want request-1/192.0.2.7", event.RequestID, event.SourceIP)
	}
	if event.TargetType != "USER" || event.TargetID != created.User.ID || event.Action != "create" {
		t.Errorf("audit target = %q/%q action %q, want USER/%q create", event.TargetType, event.TargetID, event.Action, created.User.ID)
	}
	changes := storedChanges(t, event)
	if changes["email"] != "alice@example.com" {
		t.Errorf("audit changes.email = %v, want alice@example.com", changes["email"])
	}
	if changes["displayName"] != "Alice" {
		t.Errorf("audit changes.displayName = %v, want Alice", changes["displayName"])
	}
	roles, ok := changes["roles"].([]any)
	if !ok || len(roles) != 2 || roles[0] != "ANALYST" || roles[1] != "READ_ONLY" {
		t.Errorf("audit changes.roles = %v, want [ANALYST READ_ONLY]", changes["roles"])
	}
}

func TestCreateUserRejectsDuplicateEmail(t *testing.T) {
	test := newTestService(t)
	admin := test.createAdmin(t, testEmail)
	actor := testActorFor(admin)
	createUser(t, test.service, actor, CreateUserRequest{
		Email: "alice@example.com", DisplayName: "Alice", Roles: []string{"ANALYST"},
	})
	usersBefore := countRows(t, test.database, "users")
	eventsBefore := countRows(t, test.database, "audit_events")

	_, err := test.service.CreateUser(context.Background(), actor, testClient(), CreateUserRequest{
		Email: "ALICE@example.com", DisplayName: "Other Alice", Roles: []string{"READ_ONLY"},
	})
	if !errors.Is(err, ErrUserExists) {
		t.Fatalf("CreateUser with a duplicate email = %v, want ErrUserExists", err)
	}
	if got := countRows(t, test.database, "users"); got != usersBefore {
		t.Errorf("users count = %d after the duplicate, want %d", got, usersBefore)
	}
	if got := countRows(t, test.database, "audit_events"); got != eventsBefore {
		t.Errorf("audit events = %d after the duplicate, want %d", got, eventsBefore)
	}
}

func TestCreateUserRequiresKnownRoles(t *testing.T) {
	test := newTestService(t)
	admin := test.createAdmin(t, testEmail)
	actor := testActorFor(admin)
	usersBefore := countRows(t, test.database, "users")
	eventsBefore := countRows(t, test.database, "audit_events")

	_, err := test.service.CreateUser(context.Background(), actor, testClient(), CreateUserRequest{
		Email: "alice@example.com", DisplayName: "Alice", Roles: []string{"ANALYST", "ROOT"},
	})
	if !errors.Is(err, ErrUnknownRole) {
		t.Fatalf("CreateUser with role ROOT = %v, want ErrUnknownRole", err)
	}
	if got := countRows(t, test.database, "users"); got != usersBefore {
		t.Errorf("users count = %d after an unknown role, want %d", got, usersBefore)
	}
	if got := countRows(t, test.database, "audit_events"); got != eventsBefore {
		t.Errorf("audit events = %d after an unknown role, want %d", got, eventsBefore)
	}
}

func TestCreateUserValidatesInput(t *testing.T) {
	test := newTestService(t)
	admin := test.createAdmin(t, testEmail)
	actor := testActorFor(admin)
	eventsBefore := countRows(t, test.database, "audit_events")

	tests := []struct {
		name    string
		request CreateUserRequest
		wantErr error
	}{
		{
			"invalid email",
			CreateUserRequest{Email: "Älice@example.com", DisplayName: "Alice"},
			ErrInvalidEmail,
		},
		{
			"empty display name",
			CreateUserRequest{Email: "alice@example.com", DisplayName: " "},
			ErrInvalidDisplayName,
		},
	}

	for _, testCase := range tests {
		t.Run(testCase.name, func(t *testing.T) {
			_, err := test.service.CreateUser(context.Background(), actor, testClient(), testCase.request)
			if !errors.Is(err, testCase.wantErr) {
				t.Fatalf("CreateUser error = %v, want %v", err, testCase.wantErr)
			}
			if got := countRows(t, test.database, "users"); got != 1 {
				t.Errorf("users count = %d, want 1 (only the admin)", got)
			}
			if got := countRows(t, test.database, "audit_events"); got != eventsBefore {
				t.Errorf("audit events = %d, want %d", got, eventsBefore)
			}
		})
	}
}

func TestCreateUserWithoutRoles(t *testing.T) {
	test := newTestService(t)
	admin := test.createAdmin(t, testEmail)
	created := createUser(t, test.service, testActorFor(admin), CreateUserRequest{
		Email: "alice@example.com", DisplayName: "Alice",
	})
	if len(created.Roles) != 0 {
		t.Errorf("created roles = %v, want none", created.Roles)
	}
	if created.User.Status != "INVITED" {
		t.Errorf("created status = %q, want INVITED", created.User.Status)
	}
}

func assertStateConflict(t *testing.T, err error, reason string) {
	t.Helper()
	if !errors.Is(err, ErrStateConflict) {
		t.Fatalf("error = %v, want ErrStateConflict", err)
	}
	if want := ErrStateConflict.Error() + ": " + reason; err.Error() != want {
		t.Errorf("error text = %q, want %q", err.Error(), want)
	}
}

func eventsNamed(t *testing.T, db *gorm.DB, targetID, name string) []storedAuditEvent {
	t.Helper()
	var events []storedAuditEvent
	for _, event := range auditEventsForTarget(t, db, targetID) {
		if event.EventName == name {
			events = append(events, event)
		}
	}
	return events
}

func TestUpdateUser(t *testing.T) {
	test := newTestService(t)
	admin := test.createAdmin(t, testEmail)
	actor := testActorFor(admin)
	created := createUser(t, test.service, actor, CreateUserRequest{
		Email: "alice@example.com", DisplayName: "Alice", Roles: []string{"ANALYST"},
	})

	updated, err := test.service.UpdateUser(
		context.Background(),
		actor,
		testClient(),
		created.User.ID,
		UpdateUserRequest{
			Email:       stringPointer(" Alice.New@Example.com "),
			DisplayName: stringPointer(" Alice Admin "),
			Version:     1,
		},
	)
	if err != nil {
		t.Fatalf("UpdateUser: %v", err)
	}
	if updated.User.Email != "alice.new@example.com" {
		t.Errorf("updated email = %q, want alice.new@example.com", updated.User.Email)
	}
	if updated.User.DisplayName != "Alice Admin" {
		t.Errorf("updated display name = %q, want Alice Admin", updated.User.DisplayName)
	}
	if updated.User.Version != 2 {
		t.Errorf("updated version = %d, want 2", updated.User.Version)
	}
	if len(updated.Roles) != 1 || updated.Roles[0] != "ANALYST" {
		t.Errorf("updated roles = %v, want [ANALYST]", updated.Roles)
	}

	events := eventsNamed(t, test.database, created.User.ID, "simple_siem.user.updated")
	if len(events) != 1 {
		t.Fatalf("UpdateUser wrote %d update audit events, want 1", len(events))
	}
	event := events[0]
	if event.EventCategory != "USER" || event.EventOutcome != "SUCCESS" || event.ActorType != "USER" {
		t.Errorf("update audit = %s/%s/%s, want USER/SUCCESS/USER", event.EventCategory, event.EventOutcome, event.ActorType)
	}
	if event.ActorID == nil || *event.ActorID != admin.ID {
		t.Errorf("update audit actor = %v, want %q", event.ActorID, admin.ID)
	}
	if event.TargetType != "USER" || event.TargetID != created.User.ID || event.Action != "update" {
		t.Errorf("update audit target = %q/%q action %q, want USER/%q update", event.TargetType, event.TargetID, event.Action, created.User.ID)
	}
	changes := storedChanges(t, event)
	before, ok := changes["before"].(map[string]any)
	if !ok {
		t.Fatalf("update audit changes.before = %v, want an object", changes["before"])
	}
	after, ok := changes["after"].(map[string]any)
	if !ok {
		t.Fatalf("update audit changes.after = %v, want an object", changes["after"])
	}
	if before["email"] != "alice@example.com" || before["displayName"] != "Alice" {
		t.Errorf("update audit before = %v, want the old email and display name", before)
	}
	if after["email"] != "alice.new@example.com" || after["displayName"] != "Alice Admin" {
		t.Errorf("update audit after = %v, want the new email and display name", after)
	}
	if len(before) != 2 || len(after) != 2 {
		t.Errorf("update audit before/after have %d/%d fields, want only the two changes", len(before), len(after))
	}
}

func TestUpdateUserOnlyChangedFields(t *testing.T) {
	test := newTestService(t)
	admin := test.createAdmin(t, testEmail)
	actor := testActorFor(admin)
	created := createUser(t, test.service, actor, CreateUserRequest{
		Email: "alice@example.com", DisplayName: "Alice", Roles: []string{"ANALYST"},
	})

	updated, err := test.service.UpdateUser(
		context.Background(), actor, testClient(), created.User.ID,
		UpdateUserRequest{DisplayName: stringPointer("Alice A."), Version: 1},
	)
	if err != nil {
		t.Fatalf("UpdateUser: %v", err)
	}
	if updated.User.Version != 2 {
		t.Errorf("updated version = %d, want 2", updated.User.Version)
	}
	events := eventsNamed(t, test.database, created.User.ID, "simple_siem.user.updated")
	if len(events) != 1 {
		t.Fatalf("UpdateUser wrote %d update audit events, want 1", len(events))
	}
	changes := storedChanges(t, events[0])
	before := changes["before"].(map[string]any)
	after := changes["after"].(map[string]any)
	if len(before) != 1 || before["displayName"] != "Alice" {
		t.Errorf("update audit before = %v, want only the display name", before)
	}
	if len(after) != 1 || after["displayName"] != "Alice A." {
		t.Errorf("update audit after = %v, want only the display name", after)
	}
}

func TestUpdateUserWithoutChanges(t *testing.T) {
	test := newTestService(t)
	admin := test.createAdmin(t, testEmail)
	actor := testActorFor(admin)
	created := createUser(t, test.service, actor, CreateUserRequest{
		Email: "alice@example.com", DisplayName: "Alice",
	})

	unchanged, err := test.service.UpdateUser(
		context.Background(), actor, testClient(), created.User.ID,
		UpdateUserRequest{Email: stringPointer(" ALICE@example.com "), DisplayName: stringPointer(" Alice "), Version: 1},
	)
	if err != nil {
		t.Fatalf("UpdateUser without changes: %v", err)
	}
	if unchanged.User.Version != 1 {
		t.Errorf("version after a no-op update = %d, want 1", unchanged.User.Version)
	}
	if events := eventsNamed(t, test.database, created.User.ID, "simple_siem.user.updated"); len(events) != 0 {
		t.Errorf("a no-op update wrote %d audit events, want 0", len(events))
	}

	_, err = test.service.UpdateUser(
		context.Background(), actor, testClient(), created.User.ID,
		UpdateUserRequest{Email: stringPointer("alice@example.com"), Version: 2},
	)
	if !errors.Is(err, ErrVersionConflict) {
		t.Errorf("no-op update with a stale version = %v, want ErrVersionConflict", err)
	}
}

func TestUpdateUserRejectsStaleVersion(t *testing.T) {
	test := newTestService(t)
	admin := test.createAdmin(t, testEmail)
	actor := testActorFor(admin)
	created := createUser(t, test.service, actor, CreateUserRequest{
		Email: "alice@example.com", DisplayName: "Alice",
	})

	_, err := test.service.UpdateUser(
		context.Background(), actor, testClient(), created.User.ID,
		UpdateUserRequest{DisplayName: stringPointer("Stale"), Version: 4},
	)
	if !errors.Is(err, ErrVersionConflict) {
		t.Fatalf("UpdateUser with a stale version = %v, want ErrVersionConflict", err)
	}
	stored := storedUser(t, test.database, created.User.ID)
	if stored.DisplayName != "Alice" || stored.Version != 1 {
		t.Errorf("stored user after a stale update = %+v, want Alice at version 1", stored)
	}
	if events := eventsNamed(t, test.database, created.User.ID, "simple_siem.user.updated"); len(events) != 0 {
		t.Errorf("a stale update wrote %d audit events, want 0", len(events))
	}
}

func TestUpdateUserRejectsDuplicateEmail(t *testing.T) {
	test := newTestService(t)
	admin := test.createAdmin(t, testEmail)
	actor := testActorFor(admin)
	alice := createUser(t, test.service, actor, CreateUserRequest{
		Email: "alice@example.com", DisplayName: "Alice",
	})
	createUser(t, test.service, actor, CreateUserRequest{
		Email: "bob@example.com", DisplayName: "Bob",
	})

	_, err := test.service.UpdateUser(
		context.Background(), actor, testClient(), alice.User.ID,
		UpdateUserRequest{Email: stringPointer("BOB@example.com"), Version: 1},
	)
	if !errors.Is(err, ErrUserExists) {
		t.Fatalf("UpdateUser with a duplicate email = %v, want ErrUserExists", err)
	}
	stored := storedUser(t, test.database, alice.User.ID)
	if stored.Email != "alice@example.com" || stored.Version != 1 {
		t.Errorf("stored user after a duplicate email = %+v, want the unchanged Alice", stored)
	}
}

func TestUpdateUserUnknownUser(t *testing.T) {
	test := newTestService(t)
	admin := test.createAdmin(t, testEmail)

	_, err := test.service.UpdateUser(
		context.Background(), testActorFor(admin), testClient(),
		"0190f8dc-6f43-7f0a-8b2f-9c8c0a2d3e4f",
		UpdateUserRequest{DisplayName: stringPointer("Nobody"), Version: 1},
	)
	if !errors.Is(err, ErrUserNotFound) {
		t.Errorf("UpdateUser for an unknown user = %v, want ErrUserNotFound", err)
	}
}

func TestUpdateUserValidatesInput(t *testing.T) {
	test := newTestService(t)
	admin := test.createAdmin(t, testEmail)
	actor := testActorFor(admin)
	created := createUser(t, test.service, actor, CreateUserRequest{
		Email: "alice@example.com", DisplayName: "Alice",
	})

	tests := []struct {
		name    string
		request UpdateUserRequest
		wantErr error
	}{
		{
			"invalid email",
			UpdateUserRequest{Email: stringPointer("Älice@example.com"), Version: 1},
			ErrInvalidEmail,
		},
		{
			"invalid display name",
			UpdateUserRequest{DisplayName: stringPointer(" "), Version: 1},
			ErrInvalidDisplayName,
		},
	}
	for _, testCase := range tests {
		t.Run(testCase.name, func(t *testing.T) {
			_, err := test.service.UpdateUser(
				context.Background(), actor, testClient(), created.User.ID, testCase.request,
			)
			if !errors.Is(err, testCase.wantErr) {
				t.Fatalf("UpdateUser error = %v, want %v", err, testCase.wantErr)
			}
			stored := storedUser(t, test.database, created.User.ID)
			if stored.Email != "alice@example.com" || stored.Version != 1 {
				t.Errorf("stored user after invalid input = %+v, want the unchanged Alice", stored)
			}
		})
	}
}

func TestDisableUser(t *testing.T) {
	test := newTestService(t)
	actorUser := test.createAdmin(t, testEmail)
	target := test.createAdmin(t, "target@example.com")
	test.login(t, "target@example.com", testPassword)
	test.login(t, "target@example.com", testPassword)
	targetLogin := test.login(t, "target@example.com", testPassword)
	if err := test.database.Exec(
		"INSERT INTO password_reset_tokens (user_id, token_hash, created_by, expires_at) VALUES (?, decode(repeat('ab', 32), 'hex'), ?, now() + interval '1 hour')",
		target.ID, actorUser.ID,
	).Error; err != nil {
		t.Fatalf("insert reset token: %v", err)
	}

	disabled, err := test.service.DisableUser(
		context.Background(), testActorFor(actorUser), testClient(), target.ID, target.Version,
	)
	if err != nil {
		t.Fatalf("DisableUser: %v", err)
	}
	if disabled.User.Status != "DISABLED" {
		t.Errorf("disabled status = %q, want DISABLED", disabled.User.Status)
	}
	if disabled.User.Version != 2 {
		t.Errorf("disabled version = %d, want 2", disabled.User.Version)
	}
	if disabled.User.ID != target.ID {
		t.Errorf("disabled user id = %q, want %q", disabled.User.ID, target.ID)
	}
	if got := countRows(t, test.database, "sessions"); got != 0 {
		t.Errorf("sessions count = %d after disable, want 0", got)
	}
	var unusedTokens int64
	if err := test.database.Raw(
		"SELECT count(*) FROM password_reset_tokens WHERE user_id = ? AND used_at IS NULL", target.ID,
	).Scan(&unusedTokens).Error; err != nil {
		t.Fatalf("count reset tokens: %v", err)
	}
	if unusedTokens != 0 {
		t.Errorf("unused reset tokens = %d after disable, want 0", unusedTokens)
	}
	if _, err := test.service.Authenticate(context.Background(), targetLogin.Token); !errors.Is(err, ErrUnauthenticated) {
		t.Errorf("Authenticate after disable = %v, want ErrUnauthenticated", err)
	}

	events := eventsNamed(t, test.database, target.ID, "simple_siem.user.disabled")
	if len(events) != 1 {
		t.Fatalf("DisableUser wrote %d audit events, want 1", len(events))
	}
	event := events[0]
	if event.EventCategory != "USER" || event.EventOutcome != "SUCCESS" || event.ActorType != "USER" {
		t.Errorf("disable audit = %s/%s/%s, want USER/SUCCESS/USER", event.EventCategory, event.EventOutcome, event.ActorType)
	}
	if event.ActorID == nil || *event.ActorID != actorUser.ID {
		t.Errorf("disable audit actor = %v, want %q", event.ActorID, actorUser.ID)
	}
	if event.ActorSessionID == nil || *event.ActorSessionID != testActorSessionID {
		t.Errorf("disable audit actor session = %v, want %q", event.ActorSessionID, testActorSessionID)
	}
	if event.TargetType != "USER" || event.TargetID != target.ID || event.Action != "disable" {
		t.Errorf("disable audit target = %q/%q action %q, want USER/%q disable", event.TargetType, event.TargetID, event.Action, target.ID)
	}
	changes := storedChanges(t, event)
	if changes["revokedCount"] != float64(3) {
		t.Errorf("disable audit revokedCount = %v, want 3", changes["revokedCount"])
	}
	if onCall, ok := changes["onCall"]; ok {
		t.Errorf("disable audit of an off-call user has onCall = %v, want no key", onCall)
	}
}

func TestDisableUserRejectsOwnAccount(t *testing.T) {
	test := newTestService(t)
	admin := test.createAdmin(t, testEmail)
	eventsBefore := countRows(t, test.database, "audit_events")

	_, err := test.service.DisableUser(
		context.Background(), testActorFor(admin), testClient(), admin.ID, admin.Version,
	)
	assertStateConflict(t, err, "cannot disable your own account")
	stored := storedUser(t, test.database, admin.ID)
	if stored.Status != StatusActive || stored.Version != 1 {
		t.Errorf("self-disable stored user = %+v, want ACTIVE at version 1", stored)
	}
	if got := countRows(t, test.database, "audit_events"); got != eventsBefore {
		t.Errorf("audit events = %d after a refused self-disable, want %d", got, eventsBefore)
	}
}

func TestDisableUserLastActiveAdmin(t *testing.T) {
	test := newTestService(t)
	admin := test.createAdmin(t, testEmail)
	// A disabled admin still holds ADMIN, so it passes the admin-only check
	// while leaving the target as the only active admin.
	actorUser := test.createAdmin(t, "operator@example.com")
	if err := test.database.Exec(
		"UPDATE users SET status = 'DISABLED' WHERE id = ?", actorUser.ID,
	).Error; err != nil {
		t.Fatalf("disable the operator: %v", err)
	}

	_, err := test.service.DisableUser(
		context.Background(), testActorFor(actorUser), testClient(), admin.ID, admin.Version,
	)
	assertStateConflict(t, err, "the last active admin cannot be removed")
	stored := storedUser(t, test.database, admin.ID)
	if stored.Status != StatusActive || stored.Version != 1 {
		t.Errorf("last admin after a refused disable = %+v, want ACTIVE at version 1", stored)
	}
	if events := eventsNamed(t, test.database, admin.ID, "simple_siem.user.disabled"); len(events) != 0 {
		t.Errorf("a refused last-admin disable wrote %d audit events, want 0", len(events))
	}
}

func TestDisableUserRejectsStaleVersionAndUnknownUser(t *testing.T) {
	test := newTestService(t)
	actorUser := test.createAdmin(t, testEmail)
	target := test.createAdmin(t, "target@example.com")

	_, err := test.service.DisableUser(
		context.Background(), testActorFor(actorUser), testClient(), target.ID, target.Version+1,
	)
	if !errors.Is(err, ErrVersionConflict) {
		t.Errorf("DisableUser with a stale version = %v, want ErrVersionConflict", err)
	}
	if stored := storedUser(t, test.database, target.ID); stored.Status != StatusActive {
		t.Errorf("target status after a stale disable = %q, want ACTIVE", stored.Status)
	}

	_, err = test.service.DisableUser(
		context.Background(), testActorFor(actorUser), testClient(),
		"0190f8dc-6f43-7f0a-8b2f-9c8c0a2d3e4f", 1,
	)
	if !errors.Is(err, ErrUserNotFound) {
		t.Errorf("DisableUser for an unknown user = %v, want ErrUserNotFound", err)
	}
}

func TestDisableUserRejectsAlreadyDisabled(t *testing.T) {
	test := newTestService(t)
	actorUser := test.createAdmin(t, testEmail)
	target := test.createAdmin(t, "target@example.com")
	disabled, err := test.service.DisableUser(
		context.Background(), testActorFor(actorUser), testClient(), target.ID, target.Version,
	)
	if err != nil {
		t.Fatalf("DisableUser: %v", err)
	}

	_, err = test.service.DisableUser(
		context.Background(), testActorFor(actorUser), testClient(), target.ID, disabled.User.Version,
	)
	assertStateConflict(t, err, "user is disabled")
}

func TestEnableUser(t *testing.T) {
	test := newTestService(t)
	actorUser := test.createAdmin(t, testEmail)
	target := test.createAdmin(t, "target@example.com")
	disabled, err := test.service.DisableUser(
		context.Background(), testActorFor(actorUser), testClient(), target.ID, target.Version,
	)
	if err != nil {
		t.Fatalf("DisableUser: %v", err)
	}

	enabled, err := test.service.EnableUser(
		context.Background(), testActorFor(actorUser), testClient(), target.ID, disabled.User.Version,
	)
	if err != nil {
		t.Fatalf("EnableUser: %v", err)
	}
	if enabled.User.Status != StatusActive {
		t.Errorf("enabled status = %q, want ACTIVE (the local password still exists)", enabled.User.Status)
	}
	if enabled.User.Version != 3 {
		t.Errorf("enabled version = %d, want 3", enabled.User.Version)
	}
	events := eventsNamed(t, test.database, target.ID, "simple_siem.user.enabled")
	if len(events) != 1 {
		t.Fatalf("EnableUser wrote %d audit events, want 1", len(events))
	}
	event := events[0]
	if event.EventCategory != "USER" || event.Action != "enable" || event.TargetID != target.ID {
		t.Errorf("enable audit = %s/%s/%s, want USER/enable/%s", event.EventCategory, event.Action, event.TargetID, target.ID)
	}
	if event.ActorID == nil || *event.ActorID != actorUser.ID {
		t.Errorf("enable audit actor = %v, want %q", event.ActorID, actorUser.ID)
	}
}

func TestEnableInvitedUserWithoutPassword(t *testing.T) {
	test := newTestService(t)
	admin := test.createAdmin(t, testEmail)
	actor := testActorFor(admin)
	created := createUser(t, test.service, actor, CreateUserRequest{
		Email: "alice@example.com", DisplayName: "Alice",
	})
	if err := test.database.Exec(
		"UPDATE users SET status = 'DISABLED' WHERE id = ?", created.User.ID,
	).Error; err != nil {
		t.Fatalf("disable the invited user: %v", err)
	}

	enabled, err := test.service.EnableUser(
		context.Background(), actor, testClient(), created.User.ID, created.User.Version,
	)
	if err != nil {
		t.Fatalf("EnableUser: %v", err)
	}
	if enabled.User.Status != "INVITED" {
		t.Errorf("enabled status = %q, want INVITED without a password", enabled.User.Status)
	}
}

func TestEnableUserRejectsOtherStates(t *testing.T) {
	test := newTestService(t)
	admin := test.createAdmin(t, testEmail)
	actor := testActorFor(admin)
	created := createUser(t, test.service, actor, CreateUserRequest{
		Email: "alice@example.com", DisplayName: "Alice",
	})

	_, err := test.service.EnableUser(
		context.Background(), actor, testClient(), created.User.ID, created.User.Version,
	)
	assertStateConflict(t, err, "user is not disabled")

	_, err = test.service.EnableUser(
		context.Background(), actor, testClient(),
		"0190f8dc-6f43-7f0a-8b2f-9c8c0a2d3e4f", created.User.Version,
	)
	if !errors.Is(err, ErrUserNotFound) {
		t.Errorf("EnableUser for an unknown user = %v, want ErrUserNotFound", err)
	}
}

func TestDisableUserTakesUserOffCall(t *testing.T) {
	test := newTestService(t)
	actorUser := test.createAdmin(t, testEmail)
	analyst := createUser(t, test.service, testActorFor(actorUser), CreateUserRequest{
		Email: "analyst@example.com", DisplayName: "Analyst", Roles: []string{"ANALYST"},
	})
	setUserStatus(t, test.database, analyst.User.ID, StatusActive)
	if err := test.database.Exec(
		"UPDATE users SET on_call = true WHERE id = ?", analyst.User.ID,
	).Error; err != nil {
		t.Fatalf("put the analyst on call: %v", err)
	}

	disabled, err := test.service.DisableUser(
		context.Background(), testActorFor(actorUser), testClient(), analyst.User.ID, analyst.User.Version,
	)
	if err != nil {
		t.Fatalf("DisableUser: %v", err)
	}
	if disabled.User.OnCall {
		t.Error("disabled user is still on call")
	}
	if stored := storedUser(t, test.database, analyst.User.ID); stored.OnCall {
		t.Error("stored disabled user is still on call")
	}

	events := eventsNamed(t, test.database, analyst.User.ID, "simple_siem.user.disabled")
	if len(events) != 1 {
		t.Fatalf("DisableUser wrote %d audit events, want 1", len(events))
	}
	changes := storedChanges(t, events[0])
	onCall, ok := changes["onCall"].(map[string]any)
	if !ok {
		t.Fatalf("disable audit onCall = %v, want a before/after object", changes["onCall"])
	}
	if onCall["before"] != true || onCall["after"] != false {
		t.Errorf("disable audit onCall = %v, want before true and after false", onCall)
	}
}

func TestEnableUserRejectsStaleVersion(t *testing.T) {
	test := newTestService(t)
	actorUser := test.createAdmin(t, testEmail)
	target := test.createAdmin(t, "target@example.com")
	disabled, err := test.service.DisableUser(
		context.Background(), testActorFor(actorUser), testClient(), target.ID, target.Version,
	)
	if err != nil {
		t.Fatalf("DisableUser: %v", err)
	}

	_, err = test.service.EnableUser(
		context.Background(), testActorFor(actorUser), testClient(), target.ID, disabled.User.Version-1,
	)
	if !errors.Is(err, ErrVersionConflict) {
		t.Errorf("EnableUser with a stale version = %v, want ErrVersionConflict", err)
	}
	if stored := storedUser(t, test.database, target.ID); stored.Status != "DISABLED" {
		t.Errorf("target status after a stale enable = %q, want DISABLED", stored.Status)
	}
}

func TestSetOnCall(t *testing.T) {
	test := newTestService(t)
	admin := test.createAdmin(t, testEmail)
	actor := testActorFor(admin)
	analyst := createUser(t, test.service, actor, CreateUserRequest{
		Email: "analyst@example.com", DisplayName: "Analyst", Roles: []string{"ANALYST"},
	})
	setUserStatus(t, test.database, analyst.User.ID, StatusActive)

	updated, err := test.service.SetOnCall(
		context.Background(), actor, testClient(), analyst.User.ID, true,
	)
	if err != nil {
		t.Fatalf("SetOnCall: %v", err)
	}
	if !updated.User.OnCall {
		t.Error("SetOnCall returned a user who is not on call")
	}
	if updated.User.Version != analyst.User.Version+1 {
		t.Errorf("version after SetOnCall = %d, want %d", updated.User.Version, analyst.User.Version+1)
	}
	if len(updated.Roles) != 1 || updated.Roles[0] != "ANALYST" {
		t.Errorf("roles after SetOnCall = %v, want [ANALYST]", updated.Roles)
	}

	events := eventsNamed(t, test.database, analyst.User.ID, "simple_siem.user.on_call_changed")
	if len(events) != 1 {
		t.Fatalf("SetOnCall wrote %d audit events, want 1", len(events))
	}
	event := events[0]
	if event.EventCategory != "USER" || event.EventOutcome != "SUCCESS" || event.ActorType != "USER" {
		t.Errorf("on-call audit = %s/%s/%s, want USER/SUCCESS/USER", event.EventCategory, event.EventOutcome, event.ActorType)
	}
	if event.ActorID == nil || *event.ActorID != admin.ID {
		t.Errorf("on-call audit actor = %v, want %q", event.ActorID, admin.ID)
	}
	if event.ActorSessionID == nil || *event.ActorSessionID != testActorSessionID {
		t.Errorf("on-call audit actor session = %v, want %q", event.ActorSessionID, testActorSessionID)
	}
	if event.RequestID != "request-1" || event.SourceIP == nil || *event.SourceIP != "192.0.2.7" {
		t.Errorf("on-call audit request/source = %q/%v, want request-1/192.0.2.7", event.RequestID, event.SourceIP)
	}
	if event.TargetType != "USER" || event.TargetID != analyst.User.ID || event.Action != "set_on_call" {
		t.Errorf("on-call audit target = %q/%q action %q, want USER/%q set_on_call", event.TargetType, event.TargetID, event.Action, analyst.User.ID)
	}
	changes := storedChanges(t, event)
	before, ok := changes["before"].(map[string]any)
	if !ok || before["onCall"] != false {
		t.Errorf("on-call audit before = %v, want onCall false", changes["before"])
	}
	after, ok := changes["after"].(map[string]any)
	if !ok || after["onCall"] != true {
		t.Errorf("on-call audit after = %v, want onCall true", changes["after"])
	}

	unchanged, err := test.service.SetOnCall(
		context.Background(), actor, testClient(), analyst.User.ID, true,
	)
	if err != nil {
		t.Fatalf("SetOnCall with the same value: %v", err)
	}
	if !unchanged.User.OnCall || unchanged.User.Version != updated.User.Version {
		t.Errorf("SetOnCall with the same value = %+v, want on call at version %d", unchanged.User, updated.User.Version)
	}
	if got := len(eventsNamed(t, test.database, analyst.User.ID, "simple_siem.user.on_call_changed")); got != 1 {
		t.Errorf("SetOnCall with the same value wrote another audit event (%d total, want 1)", got)
	}

	off, err := test.service.SetOnCall(
		context.Background(), actor, testClient(), analyst.User.ID, false,
	)
	if err != nil {
		t.Fatalf("SetOnCall(false): %v", err)
	}
	if off.User.OnCall || off.User.Version != updated.User.Version+1 {
		t.Errorf("SetOnCall(false) = %+v, want off call at version %d", off.User, updated.User.Version+1)
	}
	events = eventsNamed(t, test.database, analyst.User.ID, "simple_siem.user.on_call_changed")
	if len(events) != 2 {
		t.Fatalf("SetOnCall(false) left %d audit events, want 2", len(events))
	}
	changes = storedChanges(t, events[1])
	before = changes["before"].(map[string]any)
	after = changes["after"].(map[string]any)
	if before["onCall"] != true || after["onCall"] != false {
		t.Errorf("Second on-call audit = %v, want before true and after false", changes)
	}
}

func TestSetOnCallRejectsInvitedUser(t *testing.T) {
	test := newTestService(t)
	admin := test.createAdmin(t, testEmail)
	invited := createUser(t, test.service, testActorFor(admin), CreateUserRequest{
		Email: "invited@example.com", DisplayName: "Invited", Roles: []string{"ANALYST"},
	})
	eventsBefore := countRows(t, test.database, "audit_events")

	_, err := test.service.SetOnCall(
		context.Background(), testActorFor(admin), testClient(), invited.User.ID, true,
	)
	assertStateConflict(t, err, "only an active user can be on call")
	stored := storedUser(t, test.database, invited.User.ID)
	if stored.OnCall || stored.Version != invited.User.Version {
		t.Errorf("invited user after the refused on-call = %+v, want off call at version %d", stored, invited.User.Version)
	}
	if got := countRows(t, test.database, "audit_events"); got != eventsBefore {
		t.Errorf("audit events = %d after the refusal, want %d", got, eventsBefore)
	}
}

func TestSetOnCallOffForInvitedUserIsNoOp(t *testing.T) {
	test := newTestService(t)
	admin := test.createAdmin(t, testEmail)
	invited := createUser(t, test.service, testActorFor(admin), CreateUserRequest{
		Email: "invited@example.com", DisplayName: "Invited", Roles: []string{"ANALYST"},
	})

	unchanged, err := test.service.SetOnCall(
		context.Background(), testActorFor(admin), testClient(), invited.User.ID, false,
	)
	if err != nil {
		t.Fatalf("SetOnCall(false) for an invited user: %v", err)
	}
	if unchanged.User.OnCall || unchanged.User.Version != invited.User.Version {
		t.Errorf("invited user after SetOnCall(false) = %+v, want off call at version %d", unchanged.User, invited.User.Version)
	}
	if events := eventsNamed(t, test.database, invited.User.ID, "simple_siem.user.on_call_changed"); len(events) != 0 {
		t.Errorf("SetOnCall(false) for an invited user wrote %d audit events, want 0", len(events))
	}
}

func TestSetOnCallRejectsAdminTargetForNonAdmin(t *testing.T) {
	test := newTestService(t)
	if err := test.database.Exec(
		"INSERT INTO roles (name, description) VALUES ('ON_CALL_MANAGER', 'On-call manager')",
	).Error; err != nil {
		t.Fatalf("insert ON_CALL_MANAGER role: %v", err)
	}
	if err := test.database.Exec(
		"INSERT INTO role_permissions (role_name, permission) VALUES ('ON_CALL_MANAGER', 'user:on_call')",
	).Error; err != nil {
		t.Fatalf("grant ON_CALL_MANAGER user:on_call: %v", err)
	}
	admin := test.createAdmin(t, testEmail)
	manager := createUser(t, test.service, testActorFor(admin), CreateUserRequest{
		Email: "manager@example.com", DisplayName: "Manager", Roles: []string{"ON_CALL_MANAGER"},
	})
	setUserStatus(t, test.database, manager.User.ID, StatusActive)
	actor := testActorFor(manager.User)
	actor.Roles = []string{"ON_CALL_MANAGER"}
	eventsBefore := countRows(t, test.database, "audit_events")

	_, err := test.service.SetOnCall(
		context.Background(), actor, testClient(), admin.ID, true,
	)
	if !errors.Is(err, ErrForbidden) {
		t.Fatalf("SetOnCall on an admin by a non-admin = %v, want ErrForbidden", err)
	}
	stored := storedUser(t, test.database, admin.ID)
	if stored.OnCall || stored.Version != admin.Version {
		t.Errorf("admin after the refused on-call = %+v, want off call at version %d", stored, admin.Version)
	}
	if got := countRows(t, test.database, "audit_events"); got != eventsBefore {
		t.Errorf("audit events = %d after the refusal, want %d", got, eventsBefore)
	}
}

func TestAssignRole(t *testing.T) {
	test := newTestService(t)
	admin := test.createAdmin(t, testEmail)
	actor := testActorFor(admin)
	created := createUser(t, test.service, actor, CreateUserRequest{
		Email: "alice@example.com", DisplayName: "Alice",
	})

	assigned, err := test.service.AssignRole(
		context.Background(), actor, testClient(), created.User.ID, "ANALYST",
	)
	if err != nil {
		t.Fatalf("AssignRole: %v", err)
	}
	if len(assigned.Roles) != 1 || assigned.Roles[0] != "ANALYST" {
		t.Errorf("assigned roles = %v, want [ANALYST]", assigned.Roles)
	}
	if assigned.User.Version != 2 {
		t.Errorf("assigned version = %d, want 2", assigned.User.Version)
	}

	events := eventsNamed(t, test.database, created.User.ID, "simple_siem.role.assigned")
	if len(events) != 1 {
		t.Fatalf("AssignRole wrote %d audit events, want 1", len(events))
	}
	event := events[0]
	if event.EventCategory != "AUTHORIZATION" || event.EventOutcome != "SUCCESS" || event.ActorType != "USER" {
		t.Errorf("assign audit = %s/%s/%s, want AUTHORIZATION/SUCCESS/USER", event.EventCategory, event.EventOutcome, event.ActorType)
	}
	if event.ActorID == nil || *event.ActorID != admin.ID {
		t.Errorf("assign audit actor = %v, want %q", event.ActorID, admin.ID)
	}
	if event.TargetType != "USER" || event.TargetID != created.User.ID || event.Action != "assign_role" {
		t.Errorf("assign audit target = %q/%q action %q, want USER/%q assign_role", event.TargetType, event.TargetID, event.Action, created.User.ID)
	}
	if changes := storedChanges(t, event); changes["role"] != "ANALYST" {
		t.Errorf("assign audit changes = %v, want role ANALYST", changes)
	}
}

func TestAssignRoleIsNoOpWhenHeld(t *testing.T) {
	test := newTestService(t)
	admin := test.createAdmin(t, testEmail)
	actor := testActorFor(admin)
	created := createUser(t, test.service, actor, CreateUserRequest{
		Email: "alice@example.com", DisplayName: "Alice", Roles: []string{"ANALYST"},
	})

	unchanged, err := test.service.AssignRole(
		context.Background(), actor, testClient(), created.User.ID, "ANALYST",
	)
	if err != nil {
		t.Fatalf("AssignRole of a held role: %v", err)
	}
	if unchanged.User.Version != 1 {
		t.Errorf("version after assigning a held role = %d, want 1", unchanged.User.Version)
	}
	if events := eventsNamed(t, test.database, created.User.ID, "simple_siem.role.assigned"); len(events) != 0 {
		t.Errorf("assigning a held role wrote %d audit events, want 0", len(events))
	}
}

func TestAssignRoleRejectsUnknownRoleAndUser(t *testing.T) {
	test := newTestService(t)
	admin := test.createAdmin(t, testEmail)
	actor := testActorFor(admin)
	created := createUser(t, test.service, actor, CreateUserRequest{
		Email: "alice@example.com", DisplayName: "Alice",
	})

	_, err := test.service.AssignRole(
		context.Background(), actor, testClient(), created.User.ID, "ROOT",
	)
	if !errors.Is(err, ErrUnknownRole) {
		t.Errorf("AssignRole(ROOT) = %v, want ErrUnknownRole", err)
	}
	if stored := storedUser(t, test.database, created.User.ID); stored.Version != 1 {
		t.Errorf("user version after an unknown role = %d, want 1", stored.Version)
	}

	_, err = test.service.AssignRole(
		context.Background(), actor, testClient(),
		"0190f8dc-6f43-7f0a-8b2f-9c8c0a2d3e4f", "ANALYST",
	)
	if !errors.Is(err, ErrUserNotFound) {
		t.Errorf("AssignRole for an unknown user = %v, want ErrUserNotFound", err)
	}
}

func TestRemoveRole(t *testing.T) {
	test := newTestService(t)
	admin := test.createAdmin(t, testEmail)
	actor := testActorFor(admin)
	created := createUser(t, test.service, actor, CreateUserRequest{
		Email: "alice@example.com", DisplayName: "Alice", Roles: []string{"ANALYST", "READ_ONLY"},
	})

	removed, err := test.service.RemoveRole(
		context.Background(), actor, testClient(), created.User.ID, "ANALYST",
	)
	if err != nil {
		t.Fatalf("RemoveRole: %v", err)
	}
	if len(removed.Roles) != 1 || removed.Roles[0] != "READ_ONLY" {
		t.Errorf("roles after removing ANALYST = %v, want [READ_ONLY]", removed.Roles)
	}
	if removed.User.Version != 2 {
		t.Errorf("version after removing a role = %d, want 2", removed.User.Version)
	}

	events := eventsNamed(t, test.database, created.User.ID, "simple_siem.role.removed")
	if len(events) != 1 {
		t.Fatalf("RemoveRole wrote %d audit events, want 1", len(events))
	}
	event := events[0]
	if event.EventCategory != "AUTHORIZATION" || event.Action != "remove_role" || event.TargetID != created.User.ID {
		t.Errorf("remove audit = %s/%s/%s, want AUTHORIZATION/remove_role/%s", event.EventCategory, event.Action, event.TargetID, created.User.ID)
	}
	if changes := storedChanges(t, event); changes["role"] != "ANALYST" {
		t.Errorf("remove audit changes = %v, want role ANALYST", changes)
	}

	unchanged, err := test.service.RemoveRole(
		context.Background(), actor, testClient(), created.User.ID, "ANALYST",
	)
	if err != nil {
		t.Fatalf("RemoveRole of a role not held: %v", err)
	}
	if unchanged.User.Version != 2 {
		t.Errorf("version after removing a role not held = %d, want 2", unchanged.User.Version)
	}
	if events := eventsNamed(t, test.database, created.User.ID, "simple_siem.role.removed"); len(events) != 1 {
		t.Errorf("removing a role not held wrote another audit event (%d total, want 1)", len(events))
	}
}

func TestRemoveRoleRejectsUnknownRoleAndUser(t *testing.T) {
	test := newTestService(t)
	admin := test.createAdmin(t, testEmail)
	actor := testActorFor(admin)
	created := createUser(t, test.service, actor, CreateUserRequest{
		Email: "alice@example.com", DisplayName: "Alice", Roles: []string{"ANALYST"},
	})

	_, err := test.service.RemoveRole(
		context.Background(), actor, testClient(), created.User.ID, "ROOT",
	)
	if !errors.Is(err, ErrUnknownRole) {
		t.Errorf("RemoveRole(ROOT) = %v, want ErrUnknownRole", err)
	}

	_, err = test.service.RemoveRole(
		context.Background(), actor, testClient(),
		"0190f8dc-6f43-7f0a-8b2f-9c8c0a2d3e4f", "ANALYST",
	)
	if !errors.Is(err, ErrUserNotFound) {
		t.Errorf("RemoveRole for an unknown user = %v, want ErrUserNotFound", err)
	}
}

func TestRemoveLastActiveAdminRole(t *testing.T) {
	test := newTestService(t)
	admin := test.createAdmin(t, testEmail)

	_, err := test.service.RemoveRole(
		context.Background(), testActorFor(admin), testClient(), admin.ID, RoleAdmin,
	)
	assertStateConflict(t, err, "the last active admin cannot be removed")
	if stored := storedUser(t, test.database, admin.ID); stored.Version != 1 {
		t.Errorf("last admin version after a refused removal = %d, want 1", stored.Version)
	}
	if held, err := userHasRole(test.database, admin.ID, RoleAdmin); err != nil || !held {
		t.Errorf("last admin still holds ADMIN = %v (error %v), want true", held, err)
	}
	if events := eventsNamed(t, test.database, admin.ID, "simple_siem.role.removed"); len(events) != 0 {
		t.Errorf("a refused removal wrote %d audit events, want 0", len(events))
	}
}

func TestRemoveAdminRoleWithAnotherAdmin(t *testing.T) {
	test := newTestService(t)
	actorUser := test.createAdmin(t, testEmail)
	target := test.createAdmin(t, "target@example.com")

	removed, err := test.service.RemoveRole(
		context.Background(), testActorFor(actorUser), testClient(), target.ID, RoleAdmin,
	)
	if err != nil {
		t.Fatalf("RemoveRole(ADMIN) with another admin: %v", err)
	}
	if len(removed.Roles) != 0 {
		t.Errorf("target roles after removing ADMIN = %v, want none", removed.Roles)
	}
	if removed.User.Version != 2 {
		t.Errorf("target version after removing ADMIN = %d, want 2", removed.User.Version)
	}
}

func TestConcurrentLastAdminRemoval(t *testing.T) {
	test := newTestService(t)
	first := test.createAdmin(t, "first@example.com")
	second := test.createAdmin(t, "second@example.com")

	operations := []struct {
		actor  User
		target User
	}{
		{first, second},
		{second, first},
	}
	start := make(chan struct{})
	results := make([]error, len(operations))
	var wait sync.WaitGroup
	for index, operation := range operations {
		wait.Add(1)
		go func() {
			defer wait.Done()
			<-start
			_, results[index] = test.service.RemoveRole(
				context.Background(),
				testActorFor(operation.actor),
				testClient(),
				operation.target.ID,
				RoleAdmin,
			)
		}()
	}
	close(start)
	wait.Wait()

	var succeeded, conflicted int
	for _, err := range results {
		switch {
		case err == nil:
			succeeded++
		case errors.Is(err, ErrStateConflict):
			conflicted++
		default:
			t.Errorf("concurrent RemoveRole error = %v, want nil or ErrStateConflict", err)
		}
	}
	if succeeded != 1 || conflicted != 1 {
		t.Fatalf("concurrent removals = %d succeeded and %d conflicted, want 1 and 1", succeeded, conflicted)
	}

	var activeAdmins int64
	if err := test.database.Raw(`
		SELECT count(*) FROM users
		JOIN user_roles ON user_roles.user_id = users.id
		WHERE role_name = ? AND status = ?`, RoleAdmin, StatusActive,
	).Scan(&activeAdmins).Error; err != nil {
		t.Fatalf("count active admins: %v", err)
	}
	if activeAdmins != 1 {
		t.Errorf("active admins after the race = %d, want 1", activeAdmins)
	}
	var adminRoles int64
	if err := test.database.Raw(
		"SELECT count(*) FROM user_roles WHERE role_name = ?", RoleAdmin,
	).Scan(&adminRoles).Error; err != nil {
		t.Fatalf("count admin roles: %v", err)
	}
	if adminRoles != 1 {
		t.Errorf("ADMIN role rows after the race = %d, want 1", adminRoles)
	}
}

const testNewPassword = "a whole new password"

type storedResetToken struct {
	UserID    string     `gorm:"column:user_id"`
	TokenHash []byte     `gorm:"column:token_hash"`
	CreatedBy string     `gorm:"column:created_by"`
	ExpiresAt time.Time  `gorm:"column:expires_at"`
	UsedAt    *time.Time `gorm:"column:used_at"`
}

func readResetToken(t *testing.T, db *gorm.DB, userID string) storedResetToken {
	t.Helper()
	var token storedResetToken
	err := db.Raw(`
		SELECT user_id::text AS user_id, token_hash, created_by::text AS created_by, expires_at, used_at
		FROM password_reset_tokens
		WHERE user_id = ?
		ORDER BY created_at DESC
		LIMIT 1`, userID).Scan(&token).Error
	if err != nil {
		t.Fatalf("read reset token: %v", err)
	}
	if token.TokenHash == nil {
		t.Fatalf("no reset token for user %q", userID)
	}
	return token
}

func hashResetToken(t *testing.T, token string) []byte {
	t.Helper()
	raw, err := base64.RawURLEncoding.DecodeString(token)
	if err != nil {
		t.Fatalf("decode reset token: %v", err)
	}
	sum := sha256.Sum256(raw)
	return sum[:]
}

func TestCreateResetToken(t *testing.T) {
	test := newTestService(t)
	admin := test.createAdmin(t, testEmail)
	actor := testActorFor(admin)
	created := createUser(t, test.service, actor, CreateUserRequest{
		Email: "alice@example.com", DisplayName: "Alice",
	})

	token, expiresAt, err := test.service.CreateResetToken(
		context.Background(), actor, testClient(), created.User.ID,
	)
	if err != nil {
		t.Fatalf("CreateResetToken: %v", err)
	}
	raw, err := base64.RawURLEncoding.DecodeString(token)
	if err != nil || len(raw) != 32 {
		t.Errorf("reset token decodes to %d bytes (error %v), want 32", len(raw), err)
	}
	if until := time.Until(expiresAt); until < 23*time.Hour+50*time.Minute || until > 24*time.Hour+10*time.Minute {
		t.Errorf("reset token expires in %v, want about 24 hours", until)
	}

	stored := readResetToken(t, test.database, created.User.ID)
	if string(stored.TokenHash) != string(hashResetToken(t, token)) {
		t.Errorf("stored reset token hash does not match the SHA-256 of the token")
	}
	if stored.CreatedBy != admin.ID {
		t.Errorf("reset token created_by = %q, want the admin %q", stored.CreatedBy, admin.ID)
	}
	if stored.UsedAt != nil {
		t.Errorf("new reset token used_at = %v, want nil", stored.UsedAt)
	}

	events := eventsNamed(t, test.database, created.User.ID, "simple_siem.auth.password_reset_created")
	if len(events) != 1 {
		t.Fatalf("CreateResetToken wrote %d audit events, want 1", len(events))
	}
	event := events[0]
	if event.EventCategory != "AUTHENTICATION" || event.EventOutcome != "SUCCESS" || event.ActorType != "USER" {
		t.Errorf("reset-token audit = %s/%s/%s, want AUTHENTICATION/SUCCESS/USER", event.EventCategory, event.EventOutcome, event.ActorType)
	}
	if event.ActorID == nil || *event.ActorID != admin.ID {
		t.Errorf("reset-token audit actor = %v, want %q", event.ActorID, admin.ID)
	}
	if event.RequestID != "request-1" || event.SourceIP == nil || *event.SourceIP != "192.0.2.7" {
		t.Errorf("reset-token audit request/source = %q/%v, want request-1/192.0.2.7", event.RequestID, event.SourceIP)
	}
	if event.TargetType != "USER" || event.TargetID != created.User.ID || event.Action != "create_reset_token" {
		t.Errorf("reset-token audit target = %q/%q action %q, want USER/%q create_reset_token", event.TargetType, event.TargetID, event.Action, created.User.ID)
	}
	if strings.Contains(string(event.Changes), token) {
		t.Errorf("reset-token audit changes contain the token: %s", event.Changes)
	}
}

func TestCreateResetTokenInvalidatesOlderTokens(t *testing.T) {
	test := newTestService(t)
	admin := test.createAdmin(t, testEmail)
	actor := testActorFor(admin)
	created := createUser(t, test.service, actor, CreateUserRequest{
		Email: "alice@example.com", DisplayName: "Alice",
	})

	first, _, err := test.service.CreateResetToken(context.Background(), actor, testClient(), created.User.ID)
	if err != nil {
		t.Fatalf("CreateResetToken (first): %v", err)
	}
	second, _, err := test.service.CreateResetToken(context.Background(), actor, testClient(), created.User.ID)
	if err != nil {
		t.Fatalf("CreateResetToken (second): %v", err)
	}

	var unused int64
	if err := test.database.Raw(
		"SELECT count(*) FROM password_reset_tokens WHERE user_id = ? AND used_at IS NULL", created.User.ID,
	).Scan(&unused).Error; err != nil {
		t.Fatalf("count reset tokens: %v", err)
	}
	if unused != 1 {
		t.Errorf("unused reset tokens = %d after the second creation, want 1", unused)
	}
	stored := readResetToken(t, test.database, created.User.ID)
	if string(stored.TokenHash) != string(hashResetToken(t, second)) {
		t.Error("the stored reset token is not the second one")
	}

	err = test.service.UseResetToken(context.Background(), first, testNewPassword, testClient())
	if !errors.Is(err, ErrInvalidResetToken) {
		t.Errorf("UseResetToken with an invalidated token = %v, want ErrInvalidResetToken", err)
	}
}

func TestCreateResetTokenRejectsDisabledAndUnknownUser(t *testing.T) {
	test := newTestService(t)
	admin := test.createAdmin(t, testEmail)
	actor := testActorFor(admin)
	created := createUser(t, test.service, actor, CreateUserRequest{
		Email: "alice@example.com", DisplayName: "Alice",
	})
	if err := test.database.Exec(
		"UPDATE users SET status = 'DISABLED' WHERE id = ?", created.User.ID,
	).Error; err != nil {
		t.Fatalf("disable the user: %v", err)
	}

	_, _, err := test.service.CreateResetToken(context.Background(), actor, testClient(), created.User.ID)
	assertStateConflict(t, err, "user is disabled")
	if got := countRows(t, test.database, "password_reset_tokens"); got != 0 {
		t.Errorf("reset tokens = %d after a refused creation, want 0", got)
	}

	_, _, err = test.service.CreateResetToken(
		context.Background(), actor, testClient(), "0190f8dc-6f43-7f0a-8b2f-9c8c0a2d3e4f",
	)
	if !errors.Is(err, ErrUserNotFound) {
		t.Errorf("CreateResetToken for an unknown user = %v, want ErrUserNotFound", err)
	}
}

func TestUseResetTokenActivatesInvitedUser(t *testing.T) {
	test := newTestService(t)
	admin := test.createAdmin(t, testEmail)
	actor := testActorFor(admin)
	created := createUser(t, test.service, actor, CreateUserRequest{
		Email: "alice@example.com", DisplayName: "Alice", Roles: []string{"ANALYST"},
	})
	token, _, err := test.service.CreateResetToken(context.Background(), actor, testClient(), created.User.ID)
	if err != nil {
		t.Fatalf("CreateResetToken: %v", err)
	}

	if err := test.service.UseResetToken(context.Background(), token, testNewPassword, testClient()); err != nil {
		t.Fatalf("UseResetToken: %v", err)
	}

	stored := storedUser(t, test.database, created.User.ID)
	if stored.Status != StatusActive {
		t.Errorf("user status after the reset = %q, want ACTIVE", stored.Status)
	}
	if stored.Version != 2 {
		t.Errorf("user version after activating = %d, want 2", stored.Version)
	}

	var identity Identity
	if err := test.database.Where("user_id = ?", created.User.ID).First(&identity).Error; err != nil {
		t.Fatalf("read identity: %v", err)
	}
	if identity.Provider != ProviderLocal || identity.Subject != created.User.ID {
		t.Errorf("identity = %q/%q, want %q/%q", identity.Provider, identity.Subject, ProviderLocal, created.User.ID)
	}
	if identity.PasswordHash == nil {
		t.Fatal("identity password hash is nil")
	}
	matches, err := VerifyPassword(context.Background(), testNewPassword, *identity.PasswordHash)
	if err != nil || !matches {
		t.Errorf("VerifyPassword(new password) = %v/%v, want true/nil", matches, err)
	}

	login := test.login(t, "alice@example.com", testNewPassword)
	if !slices.Equal(login.Roles, []string{"ANALYST"}) {
		t.Errorf("login roles = %v, want [ANALYST]", login.Roles)
	}

	tokenRow := readResetToken(t, test.database, created.User.ID)
	if tokenRow.UsedAt == nil {
		t.Error("used_at is nil after the reset")
	}
	err = test.service.UseResetToken(context.Background(), token, testNewPassword, testClient())
	if !errors.Is(err, ErrInvalidResetToken) {
		t.Errorf("second UseResetToken = %v, want ErrInvalidResetToken", err)
	}

	events := eventsNamed(t, test.database, created.User.ID, "simple_siem.auth.password_reset_used")
	if len(events) != 1 {
		t.Fatalf("UseResetToken wrote %d audit events, want 1", len(events))
	}
	event := events[0]
	if event.EventCategory != "AUTHENTICATION" || event.EventOutcome != "SUCCESS" || event.ActorType != "ANONYMOUS" {
		t.Errorf("reset-used audit = %s/%s/%s, want AUTHENTICATION/SUCCESS/ANONYMOUS", event.EventCategory, event.EventOutcome, event.ActorType)
	}
	if event.ActorID != nil || event.ActorSessionID != nil {
		t.Errorf("reset-used audit actor = %v/%v, want nil/nil", event.ActorID, event.ActorSessionID)
	}
	if event.RequestID != "request-1" || event.SourceIP == nil || *event.SourceIP != "192.0.2.7" {
		t.Errorf("reset-used audit request/source = %q/%v, want request-1/192.0.2.7", event.RequestID, event.SourceIP)
	}
	if event.TargetType != "USER" || event.TargetID != created.User.ID || event.Action != "use_reset_token" {
		t.Errorf("reset-used audit target = %q/%q action %q, want USER/%q use_reset_token", event.TargetType, event.TargetID, event.Action, created.User.ID)
	}
	if changes := storedChanges(t, event); changes["revokedCount"] != float64(0) {
		t.Errorf("reset-used audit revokedCount = %v, want 0", changes["revokedCount"])
	}
}

func TestUseResetTokenRevokesSessionsAndChangesPassword(t *testing.T) {
	test := newTestService(t)
	actorUser := test.createAdmin(t, testEmail)
	target := test.createAdmin(t, "target@example.com")
	test.login(t, "target@example.com", testPassword)
	test.login(t, "target@example.com", testPassword)
	token, _, err := test.service.CreateResetToken(
		context.Background(), testActorFor(actorUser), testClient(), target.ID,
	)
	if err != nil {
		t.Fatalf("CreateResetToken: %v", err)
	}

	if err := test.service.UseResetToken(context.Background(), token, testNewPassword, testClient()); err != nil {
		t.Fatalf("UseResetToken: %v", err)
	}

	if got := countRows(t, test.database, "sessions"); got != 0 {
		t.Errorf("sessions count = %d after the reset, want 0", got)
	}
	if _, err := test.service.Login(
		context.Background(),
		LoginRequest{Email: "target@example.com", Password: testPassword},
		testClient(),
	); !errors.Is(err, ErrInvalidCredentials) {
		t.Errorf("login with the old password = %v, want ErrInvalidCredentials", err)
	}
	if _, err := test.service.Login(
		context.Background(),
		LoginRequest{Email: "target@example.com", Password: testNewPassword},
		testClient(),
	); err != nil {
		t.Errorf("login with the new password = %v, want nil", err)
	}
	if stored := storedUser(t, test.database, target.ID); stored.Status != StatusActive || stored.Version != 1 {
		t.Errorf("active user after the reset = %+v, want ACTIVE at version 1", stored)
	}
	var identity Identity
	if err := test.database.Where("user_id = ?", target.ID).First(&identity).Error; err != nil {
		t.Fatalf("read identity: %v", err)
	}
	if identity.Version != 2 {
		t.Errorf("identity version after the reset = %d, want 2", identity.Version)
	}
	events := eventsNamed(t, test.database, target.ID, "simple_siem.auth.password_reset_used")
	if len(events) != 1 {
		t.Fatalf("UseResetToken wrote %d audit events, want 1", len(events))
	}
	if changes := storedChanges(t, events[0]); changes["revokedCount"] != float64(2) {
		t.Errorf("reset-used audit revokedCount = %v, want 2", changes["revokedCount"])
	}
}

func TestUseResetTokenInvalidTokensDoNotHash(t *testing.T) {
	test := newTestService(t)
	admin := test.createAdmin(t, testEmail)
	actor := testActorFor(admin)
	created := createUser(t, test.service, actor, CreateUserRequest{
		Email: "alice@example.com", DisplayName: "Alice",
	})

	original := hashPasswordFunction
	hashCalls := 0
	hashPasswordFunction = func(ctx context.Context, password string) (string, error) {
		hashCalls++
		return original(ctx, password)
	}
	t.Cleanup(func() { hashPasswordFunction = original })

	used, _, err := test.service.CreateResetToken(context.Background(), actor, testClient(), created.User.ID)
	if err != nil {
		t.Fatalf("CreateResetToken (used case): %v", err)
	}
	if err := test.service.UseResetToken(context.Background(), used, testNewPassword, testClient()); err != nil {
		t.Fatalf("UseResetToken (used case): %v", err)
	}
	if hashCalls != 1 {
		t.Fatalf("a successful reset hashed %d times, want 1", hashCalls)
	}
	hashCalls = 0

	expired, _, err := test.service.CreateResetToken(context.Background(), actor, testClient(), created.User.ID)
	if err != nil {
		t.Fatalf("CreateResetToken (expired case): %v", err)
	}
	if err := test.database.Exec(
		"UPDATE password_reset_tokens SET expires_at = now() - interval '1 minute' WHERE used_at IS NULL",
	).Error; err != nil {
		t.Fatalf("expire the token: %v", err)
	}

	disabled := createUser(t, test.service, actor, CreateUserRequest{
		Email: "bob@example.com", DisplayName: "Bob",
	})
	disabledToken, _, err := test.service.CreateResetToken(context.Background(), actor, testClient(), disabled.User.ID)
	if err != nil {
		t.Fatalf("CreateResetToken (disabled case): %v", err)
	}
	if err := test.database.Exec("UPDATE users SET status = 'DISABLED' WHERE id = ?", disabled.User.ID).Error; err != nil {
		t.Fatalf("disable Bob: %v", err)
	}

	unknown := base64.RawURLEncoding.EncodeToString([]byte("01234567890123456789012345678901"))
	tests := []struct {
		name  string
		token string
	}{
		{"unknown", unknown},
		{"used", used},
		{"expired", expired},
		{"disabled user", disabledToken},
		{"malformed", "not-a-token!"},
	}
	var firstError string
	for _, testCase := range tests {
		t.Run(testCase.name, func(t *testing.T) {
			err := test.service.UseResetToken(context.Background(), testCase.token, testNewPassword, testClient())
			if !errors.Is(err, ErrInvalidResetToken) {
				t.Fatalf("UseResetToken(%s) = %v, want ErrInvalidResetToken", testCase.name, err)
			}
			if firstError == "" {
				firstError = err.Error()
			} else if err.Error() != firstError {
				t.Errorf("error text = %q, want the same as the other invalid tokens (%q)", err.Error(), firstError)
			}
			if hashCalls != 0 {
				t.Errorf("an invalid token hashed the password %d times, want 0", hashCalls)
			}
		})
	}
}

func TestUseResetTokenShortPasswordKeepsToken(t *testing.T) {
	test := newTestService(t)
	admin := test.createAdmin(t, testEmail)
	actor := testActorFor(admin)
	created := createUser(t, test.service, actor, CreateUserRequest{
		Email: "alice@example.com", DisplayName: "Alice",
	})
	token, _, err := test.service.CreateResetToken(context.Background(), actor, testClient(), created.User.ID)
	if err != nil {
		t.Fatalf("CreateResetToken: %v", err)
	}

	err = test.service.UseResetToken(context.Background(), token, strings.Repeat("a", 11), testClient())
	if !errors.Is(err, ErrPasswordLength) {
		t.Fatalf("UseResetToken with an 11-character password = %v, want ErrPasswordLength", err)
	}
	if stored := readResetToken(t, test.database, created.User.ID); stored.UsedAt != nil {
		t.Error("used_at is set after a short password, want nil")
	}
	if stored := storedUser(t, test.database, created.User.ID); stored.Status != "INVITED" {
		t.Errorf("user status after a short password = %q, want INVITED", stored.Status)
	}
	if got := countRows(t, test.database, "user_identities"); got != 1 {
		t.Errorf("identities = %d after a short password, want 1 (only the admin's)", got)
	}
	if events := eventsNamed(t, test.database, created.User.ID, "simple_siem.auth.password_reset_used"); len(events) != 0 {
		t.Errorf("a short password wrote %d reset-used audit events, want 0", len(events))
	}

	if err := test.service.UseResetToken(context.Background(), token, testNewPassword, testClient()); err != nil {
		t.Fatalf("UseResetToken with a valid password after the rejected one: %v", err)
	}
	if stored := storedUser(t, test.database, created.User.ID); stored.Status != StatusActive {
		t.Errorf("user status after the valid reset = %q, want ACTIVE", stored.Status)
	}
}

func TestResetTokenNeverStoredOrAudited(t *testing.T) {
	test := newTestService(t)
	admin := test.createAdmin(t, testEmail)
	actor := testActorFor(admin)
	created := createUser(t, test.service, actor, CreateUserRequest{
		Email: "alice@example.com", DisplayName: "Alice",
	})
	token, _, err := test.service.CreateResetToken(context.Background(), actor, testClient(), created.User.ID)
	if err != nil {
		t.Fatalf("CreateResetToken: %v", err)
	}
	if err := test.service.UseResetToken(context.Background(), token, testNewPassword, testClient()); err != nil {
		t.Fatalf("UseResetToken: %v", err)
	}

	raw, err := base64.RawURLEncoding.DecodeString(token)
	if err != nil {
		t.Fatalf("decode reset token: %v", err)
	}
	stored := readResetToken(t, test.database, created.User.ID)
	if string(stored.TokenHash) == string(raw) {
		t.Error("password_reset_tokens stores the raw token instead of its hash")
	}

	var tokenRows string
	if err := test.database.Raw(
		"SELECT COALESCE(string_agg(password_reset_tokens::text, ' '), '') FROM password_reset_tokens",
	).Scan(&tokenRows).Error; err != nil {
		t.Fatalf("read password_reset_tokens rows: %v", err)
	}
	var auditChanges string
	if err := test.database.Raw(
		"SELECT COALESCE(string_agg(changes::text, ' '), '') FROM audit_events",
	).Scan(&auditChanges).Error; err != nil {
		t.Fatalf("read audit changes: %v", err)
	}
	logged := test.logs.String()
	for _, haystack := range []string{tokenRows, auditChanges, logged} {
		if strings.Contains(haystack, token) {
			t.Errorf("the reset token appears in stored or logged data: %s", haystack)
		}
	}
}

// TestConcurrentResetTokenCreationAndDisable races the two writes that touch
// a user's unused tokens: creating one and disabling the user. A disable that
// commits after the creation must leave no usable token behind.
func TestConcurrentResetTokenCreationAndDisable(t *testing.T) {
	test := newTestService(t)
	admin := test.createAdmin(t, testEmail)
	actor := testActorFor(admin)

	const rounds = 20
	for round := 0; round < rounds; round++ {
		target := createUser(t, test.service, actor, CreateUserRequest{
			Email:       fmt.Sprintf("target%02d@example.com", round),
			DisplayName: "Target",
		})

		start := make(chan struct{})
		var wait sync.WaitGroup
		var resetErr, disableErr error
		wait.Add(2)
		go func() {
			defer wait.Done()
			<-start
			_, _, resetErr = test.service.CreateResetToken(
				context.Background(), actor, testClient(), target.User.ID,
			)
		}()
		go func() {
			defer wait.Done()
			<-start
			_, disableErr = test.service.DisableUser(
				context.Background(), actor, testClient(), target.User.ID, target.User.Version,
			)
		}()
		close(start)
		wait.Wait()

		if disableErr != nil {
			t.Fatalf("round %d: DisableUser = %v, want nil", round, disableErr)
		}
		if resetErr != nil && !errors.Is(resetErr, ErrStateConflict) {
			t.Fatalf("round %d: CreateResetToken = %v, want nil or ErrStateConflict", round, resetErr)
		}
		var unused int64
		err := test.database.Raw(
			"SELECT count(*) FROM password_reset_tokens WHERE user_id = ? AND used_at IS NULL",
			target.User.ID,
		).Scan(&unused).Error
		if err != nil {
			t.Fatalf("round %d: count reset tokens: %v", round, err)
		}
		if unused != 0 {
			t.Fatalf("round %d: disabled user has %d unused reset tokens", round, unused)
		}
	}
}

// TestConcurrentResetTokenUseAndDisable races the use of a reset token and the
// disable of its user. UseResetToken must take the user lock before the token
// lock, the same order DisableUser uses, so the pair cannot deadlock.
func TestConcurrentResetTokenUseAndDisable(t *testing.T) {
	test := newTestService(t)
	admin := test.createAdmin(t, testEmail)
	actor := testActorFor(admin)

	// The real hash runs before the transaction, so it would hide the lock
	// order; this test is about the locks, not the hashing.
	original := hashPasswordFunction
	hashPasswordFunction = func(context.Context, string) (string, error) {
		return "test-password-hash", nil
	}
	t.Cleanup(func() { hashPasswordFunction = original })

	const rounds = 20
	for round := 0; round < rounds; round++ {
		target := createUser(t, test.service, actor, CreateUserRequest{
			Email:       fmt.Sprintf("target%02d@example.com", round),
			DisplayName: "Target",
		})
		token, _, err := test.service.CreateResetToken(
			context.Background(), actor, testClient(), target.User.ID,
		)
		if err != nil {
			t.Fatalf("round %d: CreateResetToken: %v", round, err)
		}

		start := make(chan struct{})
		var wait sync.WaitGroup
		var useErr, disableErr error
		wait.Add(2)
		go func() {
			defer wait.Done()
			<-start
			useErr = test.service.UseResetToken(
				context.Background(), token, testNewPassword, testClient(),
			)
		}()
		go func() {
			defer wait.Done()
			<-start
			_, disableErr = test.service.DisableUser(
				context.Background(), actor, testClient(), target.User.ID, target.User.Version,
			)
		}()
		close(start)
		wait.Wait()

		for _, callErr := range []error{useErr, disableErr} {
			if callErr == nil {
				continue
			}
			if strings.Contains(strings.ToLower(callErr.Error()), "deadlock") {
				t.Fatalf("round %d: %v", round, callErr)
			}
			if !errors.Is(callErr, ErrInvalidResetToken) &&
				!errors.Is(callErr, ErrVersionConflict) &&
				!errors.Is(callErr, ErrStateConflict) {
				t.Fatalf("round %d: unexpected error %v", round, callErr)
			}
		}
	}
}

// insertHelpdeskRole adds a custom role with user administration permissions
// but without ADMIN. The default mapping is fixed by migration, so a test role
// is inserted directly.
func insertHelpdeskRole(t *testing.T, db *gorm.DB) {
	t.Helper()
	if err := db.Exec(
		"INSERT INTO roles (name, description) VALUES ('HELPDESK', 'Help desk')",
	).Error; err != nil {
		t.Fatalf("insert HELPDESK role: %v", err)
	}
	if err := db.Exec(`
		INSERT INTO role_permissions (role_name, permission) VALUES
		('HELPDESK', 'user:write'), ('HELPDESK', 'role:assign')`).Error; err != nil {
		t.Fatalf("grant HELPDESK permissions: %v", err)
	}
}

func TestNonAdminCannotChangeAdmins(t *testing.T) {
	test := newTestService(t)
	insertHelpdeskRole(t, test.database)
	admin := test.createAdmin(t, testEmail)
	disabledAdmin := test.createAdmin(t, "disabled-admin@example.com")
	if err := test.database.Exec(
		"UPDATE users SET status = 'DISABLED' WHERE id = ?", disabledAdmin.ID,
	).Error; err != nil {
		t.Fatalf("disable the second admin: %v", err)
	}

	helpdesk := createUser(t, test.service, testActorFor(admin), CreateUserRequest{
		Email: "helpdesk@example.com", DisplayName: "Help Desk", Roles: []string{"HELPDESK"},
	})
	actor := testActorFor(helpdesk.User)
	actor.Roles = []string{"HELPDESK"}
	ctx := context.Background()

	if _, _, err := test.service.CreateResetToken(ctx, actor, testClient(), admin.ID); !errors.Is(err, ErrForbidden) {
		t.Errorf("CreateResetToken for an admin by a non-admin = %v, want ErrForbidden", err)
	}
	if got := countRows(t, test.database, "password_reset_tokens"); got != 0 {
		t.Errorf("reset tokens = %d after the refusal, want 0", got)
	}

	_, err := test.service.UpdateUser(ctx, actor, testClient(), admin.ID, UpdateUserRequest{
		DisplayName: stringPointer("Renamed"), Version: admin.Version,
	})
	if !errors.Is(err, ErrForbidden) {
		t.Errorf("UpdateUser on an admin by a non-admin = %v, want ErrForbidden", err)
	}
	if stored := storedUser(t, test.database, admin.ID); stored.DisplayName != admin.DisplayName || stored.Version != admin.Version {
		t.Errorf("admin after the refused update = %+v, want the unchanged admin", stored)
	}

	if _, err := test.service.DisableUser(ctx, actor, testClient(), admin.ID, admin.Version); !errors.Is(err, ErrForbidden) {
		t.Errorf("DisableUser on an admin by a non-admin = %v, want ErrForbidden", err)
	}
	if stored := storedUser(t, test.database, admin.ID); stored.Status != StatusActive || stored.Version != admin.Version {
		t.Errorf("admin after the refused disable = %+v, want ACTIVE at version %d", stored, admin.Version)
	}

	if _, err := test.service.EnableUser(ctx, actor, testClient(), disabledAdmin.ID, disabledAdmin.Version); !errors.Is(err, ErrForbidden) {
		t.Errorf("EnableUser on an admin by a non-admin = %v, want ErrForbidden", err)
	}
	if stored := storedUser(t, test.database, disabledAdmin.ID); stored.Status != "DISABLED" || stored.Version != disabledAdmin.Version {
		t.Errorf("admin after the refused enable = %+v, want DISABLED at version %d", stored, disabledAdmin.Version)
	}

	if _, err := test.service.AssignRole(ctx, actor, testClient(), helpdesk.User.ID, RoleAdmin); !errors.Is(err, ErrForbidden) {
		t.Errorf("AssignRole(ADMIN) by a non-admin = %v, want ErrForbidden", err)
	}
	if held, err := userHasRole(test.database, helpdesk.User.ID, RoleAdmin); err != nil || held {
		t.Errorf("helpdesk holds ADMIN after the refused assignment = %v (error %v), want false", held, err)
	}
	if stored := storedUser(t, test.database, helpdesk.User.ID); stored.Version != helpdesk.User.Version {
		t.Errorf("helpdesk version after the refused assignment = %d, want %d", stored.Version, helpdesk.User.Version)
	}

	if _, err := test.service.RemoveRole(ctx, actor, testClient(), admin.ID, RoleAdmin); !errors.Is(err, ErrForbidden) {
		t.Errorf("RemoveRole(ADMIN) by a non-admin = %v, want ErrForbidden", err)
	}
	if held, err := userHasRole(test.database, admin.ID, RoleAdmin); err != nil || !held {
		t.Errorf("admin still holds ADMIN after the refused removal = %v (error %v), want true", held, err)
	}

	refusedEvents := map[string]string{
		admin.ID:         "simple_siem.auth.password_reset_created",
		disabledAdmin.ID: "simple_siem.user.enabled",
		helpdesk.User.ID: "simple_siem.role.assigned",
	}
	for targetID, name := range refusedEvents {
		if events := eventsNamed(t, test.database, targetID, name); len(events) != 0 {
			t.Errorf("a refused %s wrote %d audit events, want 0", name, len(events))
		}
	}
}

func TestNonAdminCannotGrantAdminOrChangeAdminRoles(t *testing.T) {
	test := newTestService(t)
	insertHelpdeskRole(t, test.database)
	admin := test.createAdmin(t, testEmail)
	adminActor := testActorFor(admin)
	helpdesk := createUser(t, test.service, adminActor, CreateUserRequest{
		Email: "helpdesk@example.com", DisplayName: "Help Desk", Roles: []string{"HELPDESK"},
	})
	actor := testActorFor(helpdesk.User)
	actor.Roles = []string{"HELPDESK"}
	ctx := context.Background()

	if _, err := test.service.CreateUser(ctx, actor, testClient(), CreateUserRequest{
		Email: "new-admin@example.com", DisplayName: "New Admin", Roles: []string{RoleAdmin},
	}); !errors.Is(err, ErrForbidden) {
		t.Errorf("CreateUser with ADMIN by a non-admin = %v, want ErrForbidden", err)
	}
	var created int64
	if err := test.database.Raw(
		"SELECT count(*) FROM users WHERE email = ?", "new-admin@example.com",
	).Scan(&created).Error; err != nil {
		t.Fatalf("count the refused admin: %v", err)
	}
	if created != 0 {
		t.Errorf("the refused admin user exists, want no row")
	}

	createUser(t, test.service, adminActor, CreateUserRequest{
		Email: "second-admin@example.com", DisplayName: "Second Admin", Roles: []string{RoleAdmin},
	})

	if _, err := test.service.AssignRole(ctx, adminActor, testClient(), admin.ID, "ANALYST"); err != nil {
		t.Fatalf("AssignRole(ANALYST) by an admin: %v", err)
	}
	if _, err := test.service.AssignRole(ctx, actor, testClient(), admin.ID, "READ_ONLY"); !errors.Is(err, ErrForbidden) {
		t.Errorf("AssignRole(READ_ONLY) on an admin by a non-admin = %v, want ErrForbidden", err)
	}
	if _, err := test.service.RemoveRole(ctx, actor, testClient(), admin.ID, "ANALYST"); !errors.Is(err, ErrForbidden) {
		t.Errorf("RemoveRole(ANALYST) on an admin by a non-admin = %v, want ErrForbidden", err)
	}
	updated, err := test.service.GetUser(ctx, admin.ID)
	if err != nil {
		t.Fatalf("GetUser(admin): %v", err)
	}
	if !slices.Contains(updated.Roles, "ANALYST") || slices.Contains(updated.Roles, "READ_ONLY") {
		t.Errorf("admin roles after the refusals = %v, want ANALYST without READ_ONLY", updated.Roles)
	}
}

func TestAssignAdminVoidsResetTokens(t *testing.T) {
	test := newTestService(t)
	admin := test.createAdmin(t, testEmail)
	actor := testActorFor(admin)
	target := createUser(t, test.service, actor, CreateUserRequest{
		Email: "target@example.com", DisplayName: "Target",
	})
	token, _, err := test.service.CreateResetToken(
		context.Background(), actor, testClient(), target.User.ID,
	)
	if err != nil {
		t.Fatalf("CreateResetToken: %v", err)
	}

	if _, err := test.service.AssignRole(
		context.Background(), actor, testClient(), target.User.ID, RoleAdmin,
	); err != nil {
		t.Fatalf("AssignRole(ADMIN): %v", err)
	}

	var unused int64
	if err := test.database.Raw(
		"SELECT count(*) FROM password_reset_tokens WHERE user_id = ? AND used_at IS NULL",
		target.User.ID,
	).Scan(&unused).Error; err != nil {
		t.Fatalf("count reset tokens: %v", err)
	}
	if unused != 0 {
		t.Errorf("unused reset tokens after promotion = %d, want 0", unused)
	}
	if err := test.service.UseResetToken(
		context.Background(), token, testNewPassword, testClient(),
	); !errors.Is(err, ErrInvalidResetToken) {
		t.Errorf("UseResetToken after promotion = %v, want ErrInvalidResetToken", err)
	}
}
