package v1beta1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"sigs.k8s.io/controller-runtime/pkg/scheme"
)

var (
	// GroupVersion is the group version used to register these objects.
	GroupVersion = schema.GroupVersion{Group: "furnace.io", Version: "v1beta1"}

	// SchemeBuilder is used to add functions to this group's scheme.
	SchemeBuilder = &scheme.Builder{GroupVersion: GroupVersion}

	// AddToScheme adds the types in this group-version to the given scheme.
	AddToScheme = SchemeBuilder.AddToScheme
)

func init() {
	SchemeBuilder.Register(&FurnaceUser{}, &FurnaceUserList{})
	SchemeBuilder.Register(&FurnaceGroup{}, &FurnaceGroupList{})
}

// ── FurnaceUser DeepCopy ────────────────────────────────────────────────────

func (in *FurnaceUser) DeepCopyObject() runtime.Object { return in.DeepCopy() }

func (in *FurnaceUser) DeepCopy() *FurnaceUser {
	if in == nil {
		return nil
	}
	out := new(FurnaceUser)
	in.DeepCopyInto(out)
	return out
}

func (in *FurnaceUser) DeepCopyInto(out *FurnaceUser) {
	*out = *in
	out.TypeMeta = in.TypeMeta
	in.ObjectMeta.DeepCopyInto(&out.ObjectMeta)
	in.Spec.DeepCopyInto(&out.Spec)
	in.Status.DeepCopyInto(&out.Status)
}

func (in *FurnaceUserSpec) DeepCopyInto(out *FurnaceUserSpec) {
	*out = *in
	if in.Groups != nil {
		out.Groups = make([]string, len(in.Groups))
		copy(out.Groups, in.Groups)
	}
}

func (in *FurnaceUserStatus) DeepCopyInto(out *FurnaceUserStatus) {
	*out = *in
	if in.Conditions != nil {
		out.Conditions = make([]metav1.Condition, len(in.Conditions))
		copy(out.Conditions, in.Conditions)
	}
}

// ── FurnaceUserList DeepCopy ────────────────────────────────────────────────

func (in *FurnaceUserList) DeepCopyObject() runtime.Object { return in.DeepCopy() }

func (in *FurnaceUserList) DeepCopy() *FurnaceUserList {
	if in == nil {
		return nil
	}
	out := new(FurnaceUserList)
	in.DeepCopyInto(out)
	return out
}

func (in *FurnaceUserList) DeepCopyInto(out *FurnaceUserList) {
	*out = *in
	out.TypeMeta = in.TypeMeta
	in.ListMeta.DeepCopyInto(&out.ListMeta)
	if in.Items != nil {
		out.Items = make([]FurnaceUser, len(in.Items))
		for i := range in.Items {
			in.Items[i].DeepCopyInto(&out.Items[i])
		}
	}
}

// ── FurnaceGroup DeepCopy ───────────────────────────────────────────────────

func (in *FurnaceGroup) DeepCopyObject() runtime.Object { return in.DeepCopy() }

func (in *FurnaceGroup) DeepCopy() *FurnaceGroup {
	if in == nil {
		return nil
	}
	out := new(FurnaceGroup)
	in.DeepCopyInto(out)
	return out
}

func (in *FurnaceGroup) DeepCopyInto(out *FurnaceGroup) {
	*out = *in
	out.TypeMeta = in.TypeMeta
	in.ObjectMeta.DeepCopyInto(&out.ObjectMeta)
	out.Spec = in.Spec
	in.Status.DeepCopyInto(&out.Status)
}

func (in *FurnaceGroupStatus) DeepCopyInto(out *FurnaceGroupStatus) {
	*out = *in
	if in.Conditions != nil {
		out.Conditions = make([]metav1.Condition, len(in.Conditions))
		copy(out.Conditions, in.Conditions)
	}
}

// ── FurnaceGroupList DeepCopy ───────────────────────────────────────────────

func (in *FurnaceGroupList) DeepCopyObject() runtime.Object { return in.DeepCopy() }

func (in *FurnaceGroupList) DeepCopy() *FurnaceGroupList {
	if in == nil {
		return nil
	}
	out := new(FurnaceGroupList)
	in.DeepCopyInto(out)
	return out
}

func (in *FurnaceGroupList) DeepCopyInto(out *FurnaceGroupList) {
	*out = *in
	out.TypeMeta = in.TypeMeta
	in.ListMeta.DeepCopyInto(&out.ListMeta)
	if in.Items != nil {
		out.Items = make([]FurnaceGroup, len(in.Items))
		for i := range in.Items {
			in.Items[i].DeepCopyInto(&out.Items[i])
		}
	}
}
