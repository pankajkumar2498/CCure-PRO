import CcureModal from "./CcureModal";

/** Official drawer presentation reuses the modal's portal, isolation and focus. */
export default function CcureDrawer({ placement = "right", ...props }) {
  return <CcureModal {...props} placement={placement} />;
}
