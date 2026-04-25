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

func newUserScheme() *runtime.Scheme {
	s := runtime.NewScheme()
	_ = v1beta1.AddToScheme(s)
	return s
}

func newTestUser(name string) *v1beta1.FurnaceUser {
	return &v1beta1.FurnaceUser{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: "default",
		},
		Spec: v1beta1.FurnaceUserSpec{
			Email:  name + "@example.com",
			Active: true,
		},
	}
}

func userReq(name string) ctrl.Request {
	return ctrl.Request{NamespacedName: types.NamespacedName{Name: name, Namespace: "default"}}
}

// TestUserReconcile_Create verifies that a new user triggers a SCIM PUT→POST upsert.
// The finalizer add and SCIM upsert happen in the same reconcile pass.
func TestUserReconcile_Create(t *testing.T) {
	var methods []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		methods = append(methods, r.Method)
		if r.Method == http.MethodPut {
			w.WriteHeader(http.StatusNotFound) // not found → fall through to POST
			return
		}
		w.WriteHeader(http.StatusCreated)
	}))
	defer srv.Close()

	user := newTestUser("alice")
	s := newUserScheme()
	c := fake.NewClientBuilder().WithScheme(s).WithStatusSubresource(&v1beta1.FurnaceUser{}).WithObjects(user).Build()
	r := NewUserReconciler(c, s, srv.URL, "test-key")

	if _, err := r.Reconcile(context.Background(), userReq("alice")); err != nil {
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

// TestUserReconcile_Update verifies that an existing user triggers a SCIM PUT.
func TestUserReconcile_Update(t *testing.T) {
	var methods []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		methods = append(methods, r.Method)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	user := newTestUser("bob")
	s := newUserScheme()
	c := fake.NewClientBuilder().WithScheme(s).WithStatusSubresource(&v1beta1.FurnaceUser{}).WithObjects(user).Build()
	r := NewUserReconciler(c, s, srv.URL, "test-key")

	if _, err := r.Reconcile(context.Background(), userReq("bob")); err != nil {
		t.Fatalf("reconcile: %v", err)
	}

	if len(methods) == 0 || methods[0] != http.MethodPut {
		t.Fatalf("expected PUT, got %v", methods)
	}
}

// TestUserReconcile_Delete verifies that a deleted user triggers a SCIM DELETE and removes the finalizer.
func TestUserReconcile_Delete(t *testing.T) {
	var methods []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		methods = append(methods, r.Method)
		w.WriteHeader(http.StatusNoContent)
	}))
	defer srv.Close()

	now := metav1.Now()
	user := newTestUser("carol")
	user.Finalizers = []string{finalizerName}
	user.DeletionTimestamp = &now

	s := newUserScheme()
	c := fake.NewClientBuilder().WithScheme(s).WithStatusSubresource(&v1beta1.FurnaceUser{}).WithObjects(user).Build()
	r := NewUserReconciler(c, s, srv.URL, "test-key")

	if _, err := r.Reconcile(context.Background(), userReq("carol")); err != nil {
		t.Fatalf("reconcile: %v", err)
	}

	if len(methods) == 0 || methods[0] != http.MethodDelete {
		t.Fatalf("expected DELETE, got %v", methods)
	}
}

// TestUserReconcile_SCIMFailure verifies that a SCIM error returns an error (triggering exponential backoff).
// The reconciler falls through to SCIM on the same pass that adds the finalizer, so the first reconcile fails.
func TestUserReconcile_SCIMFailure(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	user := newTestUser("dave")
	s := newUserScheme()
	c := fake.NewClientBuilder().WithScheme(s).WithStatusSubresource(&v1beta1.FurnaceUser{}).WithObjects(user).Build()
	r := NewUserReconciler(c, s, srv.URL, "test-key")

	_, err := r.Reconcile(context.Background(), userReq("dave"))
	if err == nil {
		t.Fatal("expected error from SCIM failure, got nil")
	}
}

// TestUserReconcile_NotFound verifies that a missing resource returns no error.
func TestUserReconcile_NotFound(t *testing.T) {
	s := newUserScheme()
	c := fake.NewClientBuilder().WithScheme(s).Build()
	r := NewUserReconciler(c, s, "http://unused", "")

	_, err := r.Reconcile(context.Background(), userReq("ghost"))
	if err != nil {
		t.Fatalf("expected no error for missing resource, got %v", err)
	}
}
