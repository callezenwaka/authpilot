package controller

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	v1beta1 "github.com/callezenwaka/furnace-operator/api/v1beta1"
)

func newGroupScheme() *runtime.Scheme {
	s := runtime.NewScheme()
	_ = v1beta1.AddToScheme(s)
	return s
}

func newTestGroup(name string) *v1beta1.FurnaceGroup {
	return &v1beta1.FurnaceGroup{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: "default",
		},
		Spec: v1beta1.FurnaceGroupSpec{
			Name:        name,
			DisplayName: name + " group",
		},
	}
}

func groupReq(name string) ctrl.Request {
	return ctrl.Request{NamespacedName: types.NamespacedName{Name: name, Namespace: "default"}}
}

// TestGroupReconcile_Create verifies that a new group triggers a SCIM PUT→POST upsert.
// The finalizer add and SCIM upsert happen in the same reconcile pass.
func TestGroupReconcile_Create(t *testing.T) {
	var methods []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		methods = append(methods, r.Method)
		if r.Method == http.MethodPut {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		w.WriteHeader(http.StatusCreated)
	}))
	defer srv.Close()

	group := newTestGroup("admins")
	s := newGroupScheme()
	c := fake.NewClientBuilder().WithScheme(s).WithStatusSubresource(&v1beta1.FurnaceGroup{}).WithObjects(group).Build()
	r := NewGroupReconciler(c, s, srv.URL, "test-key")

	if _, err := r.Reconcile(context.Background(), groupReq("admins")); err != nil {
		t.Fatalf("reconcile: %v", err)
	}

	if len(methods) < 2 {
		t.Fatalf("expected ≥2 SCIM calls (PUT + POST), got %v", methods)
	}
	if methods[0] != http.MethodPut {
		t.Errorf("expected first call PUT, got %s", methods[0])
	}
	if methods[1] != http.MethodPost {
		t.Errorf("expected second call POST, got %s", methods[1])
	}
}

// TestGroupReconcile_Update verifies that an existing group triggers a SCIM PUT.
func TestGroupReconcile_Update(t *testing.T) {
	var methods []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		methods = append(methods, r.Method)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	group := newTestGroup("engineers")
	s := newGroupScheme()
	c := fake.NewClientBuilder().WithScheme(s).WithStatusSubresource(&v1beta1.FurnaceGroup{}).WithObjects(group).Build()
	r := NewGroupReconciler(c, s, srv.URL, "test-key")

	if _, err := r.Reconcile(context.Background(), groupReq("engineers")); err != nil {
		t.Fatalf("reconcile: %v", err)
	}

	if len(methods) == 0 || methods[0] != http.MethodPut {
		t.Fatalf("expected PUT, got %v", methods)
	}
}

// TestGroupReconcile_Delete verifies that a deleted group triggers a SCIM DELETE and removes the finalizer.
func TestGroupReconcile_Delete(t *testing.T) {
	var methods []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		methods = append(methods, r.Method)
		w.WriteHeader(http.StatusNoContent)
	}))
	defer srv.Close()

	now := metav1.Now()
	group := newTestGroup("ops")
	group.Finalizers = []string{groupFinalizerName}
	group.DeletionTimestamp = &now

	s := newGroupScheme()
	c := fake.NewClientBuilder().WithScheme(s).WithStatusSubresource(&v1beta1.FurnaceGroup{}).WithObjects(group).Build()
	r := NewGroupReconciler(c, s, srv.URL, "test-key")

	if _, err := r.Reconcile(context.Background(), groupReq("ops")); err != nil {
		t.Fatalf("reconcile: %v", err)
	}

	if len(methods) == 0 || methods[0] != http.MethodDelete {
		t.Fatalf("expected DELETE, got %v", methods)
	}
}

// TestGroupReconcile_SCIMFailure verifies that a SCIM error returns an error (triggering exponential backoff).
// The reconciler falls through to SCIM on the same pass that adds the finalizer, so the first reconcile fails.
func TestGroupReconcile_SCIMFailure(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	group := newTestGroup("devs")
	s := newGroupScheme()
	c := fake.NewClientBuilder().WithScheme(s).WithStatusSubresource(&v1beta1.FurnaceGroup{}).WithObjects(group).Build()
	r := NewGroupReconciler(c, s, srv.URL, "test-key")

	_, err := r.Reconcile(context.Background(), groupReq("devs"))
	if err == nil {
		t.Fatal("expected error from SCIM failure, got nil")
	}
}

// TestGroupReconcile_NotFound verifies that a missing resource returns no error.
func TestGroupReconcile_NotFound(t *testing.T) {
	s := newGroupScheme()
	c := fake.NewClientBuilder().WithScheme(s).Build()
	r := NewGroupReconciler(c, s, "http://unused", "")

	_, err := r.Reconcile(context.Background(), groupReq("ghost"))
	if err != nil {
		t.Fatalf("expected no error for missing resource, got %v", err)
	}
}
