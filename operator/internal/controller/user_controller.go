// Package controller implements the reconciliation loops for FurnaceUser
// and FurnaceGroup custom resources.
//
// Each reconciler watches its CRD and syncs the desired spec to Furnace
// via the SCIM 2.0 API using the existing /scim/v2/Users and /scim/v2/Groups
// endpoints. The SCIM endpoint URL and bearer key are injected at startup
// from environment variables (FURNACE_SCIM_URL, FURNACE_SCIM_KEY).
package controller

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	"sigs.k8s.io/controller-runtime/pkg/log"

	v1beta1 "github.com/callezenwaka/furnace-operator/api/v1beta1"
)

const finalizerName = "furnace.io/user-finalizer"

// UserReconciler reconciles FurnaceUser objects.
type UserReconciler struct {
	client.Client
	Scheme   *runtime.Scheme
	SCIMURL  string // e.g. "http://furnace:8025/scim/v2"
	SCIMKey  string // bearer token for SCIM requests
	http     *http.Client
}

func NewUserReconciler(c client.Client, scheme *runtime.Scheme, scimURL, scimKey string) *UserReconciler {
	return &UserReconciler{
		Client:  c,
		Scheme:  scheme,
		SCIMURL: scimURL,
		SCIMKey: scimKey,
		http:    &http.Client{Timeout: 10 * time.Second},
	}
}

// +kubebuilder:rbac:groups=furnace.io,resources=furnaceusers,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=furnace.io,resources=furnaceusers/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=furnace.io,resources=furnaceusers/finalizers,verbs=update

func (r *UserReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	logger := log.FromContext(ctx)

	var user v1beta1.FurnaceUser
	if err := r.Get(ctx, req.NamespacedName, &user); err != nil {
		if errors.IsNotFound(err) {
			return ctrl.Result{}, nil
		}
		return ctrl.Result{}, err
	}

	// Handle deletion via finalizer.
	if !user.DeletionTimestamp.IsZero() {
		if controllerutil.ContainsFinalizer(&user, finalizerName) {
			if err := r.scimDeleteUser(ctx, user.Name); err != nil {
				logger.Error(err, "failed to delete user from Furnace")
				r.setCondition(&user, metav1.ConditionUnknown, "Pending", err.Error())
				_ = r.Status().Update(ctx, &user)
				return ctrl.Result{}, err
			}
			controllerutil.RemoveFinalizer(&user, finalizerName)
			if err := r.Update(ctx, &user); err != nil {
				return ctrl.Result{}, err
			}
		}
		return ctrl.Result{}, nil
	}

	// Add finalizer on first reconcile.
	if !controllerutil.ContainsFinalizer(&user, finalizerName) {
		controllerutil.AddFinalizer(&user, finalizerName)
		if err := r.Update(ctx, &user); err != nil {
			return ctrl.Result{}, err
		}
	}

	// Upsert: try PUT first (idempotent), fall back to POST on 404.
	if err := r.scimUpsertUser(ctx, &user); err != nil {
		logger.Error(err, "failed to upsert user in Furnace")
		r.setCondition(&user, metav1.ConditionFalse, "Failed", err.Error())
		_ = r.Status().Update(ctx, &user)
		return ctrl.Result{}, err
	}

	r.setCondition(&user, metav1.ConditionTrue, "Synced", "user synced to Furnace")
	_ = r.Status().Update(ctx, &user)
	return ctrl.Result{}, nil
}

func (r *UserReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&v1beta1.FurnaceUser{}).
		Complete(r)
}

// ── SCIM helpers ─────────────────────────────────────────────────────────────

func (r *UserReconciler) scimUpsertUser(ctx context.Context, user *v1beta1.FurnaceUser) error {
	body := map[string]any{
		"schemas":     []string{"urn:ietf:params:scim:schemas:core:2.0:User"},
		"id":          user.Name,
		"userName":    user.Spec.Email,
		"displayName": user.Spec.DisplayName,
		"active":      user.Spec.Active,
	}
	if len(user.Spec.Groups) > 0 {
		groups := make([]map[string]string, 0, len(user.Spec.Groups))
		for _, g := range user.Spec.Groups {
			groups = append(groups, map[string]string{"value": g})
		}
		body["groups"] = groups
	}

	// Try PUT first.
	status, err := r.scimRequest(ctx, http.MethodPut, "/Users/"+user.Name, body)
	if err != nil {
		return err
	}
	if status == http.StatusNotFound {
		// User doesn't exist yet — create it.
		status, err = r.scimRequest(ctx, http.MethodPost, "/Users", body)
		if err != nil {
			return err
		}
	}
	if status >= 400 {
		return fmt.Errorf("SCIM returned %d", status)
	}
	return nil
}

func (r *UserReconciler) scimDeleteUser(ctx context.Context, id string) error {
	status, err := r.scimRequest(ctx, http.MethodDelete, "/Users/"+id, nil)
	if err != nil {
		return err
	}
	if status == http.StatusNotFound {
		return nil // already gone
	}
	if status >= 400 {
		return fmt.Errorf("SCIM delete returned %d", status)
	}
	return nil
}

func (r *UserReconciler) scimRequest(ctx context.Context, method, path string, body map[string]any) (int, error) {
	var reqBody io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return 0, err
		}
		reqBody = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, r.SCIMURL+path, reqBody)
	if err != nil {
		return 0, err
	}
	req.Header.Set("Accept", "application/scim+json")
	if body != nil {
		req.Header.Set("Content-Type", "application/scim+json")
	}
	if r.SCIMKey != "" {
		req.Header.Set("Authorization", "Bearer "+r.SCIMKey)
	}
	resp, err := r.http.Do(req)
	if err != nil {
		return 0, err
	}
	resp.Body.Close()
	return resp.StatusCode, nil
}

func (r *UserReconciler) setCondition(user *v1beta1.FurnaceUser, status metav1.ConditionStatus, reason, message string) {
	now := metav1.Now()
	for i, c := range user.Status.Conditions {
		if c.Type == "Synced" {
			user.Status.Conditions[i].Status = status
			user.Status.Conditions[i].Reason = reason
			user.Status.Conditions[i].Message = message
			user.Status.Conditions[i].LastTransitionTime = now
			return
		}
	}
	user.Status.Conditions = append(user.Status.Conditions, metav1.Condition{
		Type:               "Synced",
		Status:             status,
		Reason:             reason,
		Message:            message,
		LastTransitionTime: now,
	})
}
