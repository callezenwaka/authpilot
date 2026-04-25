package controller

import (
	"context"
	"fmt"
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

const groupFinalizerName = "furnace.io/group-finalizer"

// GroupReconciler reconciles FurnaceGroup objects.
type GroupReconciler struct {
	client.Client
	Scheme  *runtime.Scheme
	SCIMURL string
	SCIMKey string
	http    *http.Client
}

func NewGroupReconciler(c client.Client, scheme *runtime.Scheme, scimURL, scimKey string) *GroupReconciler {
	return &GroupReconciler{
		Client:  c,
		Scheme:  scheme,
		SCIMURL: scimURL,
		SCIMKey: scimKey,
		http:    &http.Client{Timeout: 10 * time.Second},
	}
}

// +kubebuilder:rbac:groups=furnace.io,resources=furnacegroups,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=furnace.io,resources=furnacegroups/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=furnace.io,resources=furnacegroups/finalizers,verbs=update

func (r *GroupReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	logger := log.FromContext(ctx)

	var group v1beta1.FurnaceGroup
	if err := r.Get(ctx, req.NamespacedName, &group); err != nil {
		if errors.IsNotFound(err) {
			return ctrl.Result{}, nil
		}
		return ctrl.Result{}, err
	}

	// Handle deletion via finalizer.
	if !group.DeletionTimestamp.IsZero() {
		if controllerutil.ContainsFinalizer(&group, groupFinalizerName) {
			if err := r.scimDeleteGroup(ctx, group.Name); err != nil {
				logger.Error(err, "failed to delete group from Furnace")
				r.setCondition(&group, metav1.ConditionUnknown, "Pending", err.Error())
				_ = r.Status().Update(ctx, &group)
				return ctrl.Result{}, err
			}
			controllerutil.RemoveFinalizer(&group, groupFinalizerName)
			if err := r.Update(ctx, &group); err != nil {
				return ctrl.Result{}, err
			}
		}
		return ctrl.Result{}, nil
	}

	// Add finalizer on first reconcile.
	if !controllerutil.ContainsFinalizer(&group, groupFinalizerName) {
		controllerutil.AddFinalizer(&group, groupFinalizerName)
		if err := r.Update(ctx, &group); err != nil {
			return ctrl.Result{}, err
		}
	}

	// Upsert: try PUT first (idempotent), fall back to POST on 404.
	if err := r.scimUpsertGroup(ctx, &group); err != nil {
		logger.Error(err, "failed to upsert group in Furnace")
		r.setCondition(&group, metav1.ConditionFalse, "Failed", err.Error())
		_ = r.Status().Update(ctx, &group)
		return ctrl.Result{}, err
	}

	r.setCondition(&group, metav1.ConditionTrue, "Synced", "group synced to Furnace")
	_ = r.Status().Update(ctx, &group)
	return ctrl.Result{}, nil
}

func (r *GroupReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&v1beta1.FurnaceGroup{}).
		Complete(r)
}

// ── SCIM helpers ─────────────────────────────────────────────────────────────

func (r *GroupReconciler) scimUpsertGroup(ctx context.Context, group *v1beta1.FurnaceGroup) error {
	body := map[string]any{
		"schemas":     []string{"urn:ietf:params:scim:schemas:core:2.0:Group"},
		"id":          group.Name,
		"displayName": group.Spec.DisplayName,
		"externalId":  group.Spec.Name,
	}

	// Try PUT first.
	status, err := r.scimGroupRequest(ctx, http.MethodPut, "/Groups/"+group.Name, body)
	if err != nil {
		return err
	}
	if status == http.StatusNotFound {
		status, err = r.scimGroupRequest(ctx, http.MethodPost, "/Groups", body)
		if err != nil {
			return err
		}
	}
	if status >= 400 {
		return fmt.Errorf("SCIM returned %d", status)
	}
	return nil
}

func (r *GroupReconciler) scimDeleteGroup(ctx context.Context, id string) error {
	status, err := r.scimGroupRequest(ctx, http.MethodDelete, "/Groups/"+id, nil)
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

func (r *GroupReconciler) scimGroupRequest(ctx context.Context, method, path string, body map[string]any) (int, error) {
	ur := &UserReconciler{
		SCIMURL: r.SCIMURL,
		SCIMKey: r.SCIMKey,
		http:    r.http,
	}
	return ur.scimRequest(ctx, method, path, body)
}

func (r *GroupReconciler) setCondition(group *v1beta1.FurnaceGroup, status metav1.ConditionStatus, reason, message string) {
	now := metav1.Now()
	for i, c := range group.Status.Conditions {
		if c.Type == "Synced" {
			group.Status.Conditions[i].Status = status
			group.Status.Conditions[i].Reason = reason
			group.Status.Conditions[i].Message = message
			group.Status.Conditions[i].LastTransitionTime = now
			return
		}
	}
	group.Status.Conditions = append(group.Status.Conditions, metav1.Condition{
		Type:               "Synced",
		Status:             status,
		Reason:             reason,
		Message:            message,
		LastTransitionTime: now,
	})
}
