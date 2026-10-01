/**
 * src/shell/layout/ProductFrame.jsx — the frame a shared page renders in.
 * ─────────────────────────────────────────────────────────────────────────────
 * The platform's shared screens (users, organisations, roles, email domains,
 * audit logs) belong to no product, but a person reaches them from inside one,
 * and they should stay inside that product's navigation rather than drop into
 * a bare page. The shell cannot import a product's layout, so the composition
 * root supplies it: `<ProductFrameProvider frame={SomeLayout}>`. A shared page
 * renders `<ProductFrame>` and gets whichever layout the root chose.
 *
 * With no provider — a shell page rendered on its own — the frame is the
 * platform's own `PlatformLayout`. Props a page passes (`pageTitle`,
 * `saveStatus`, …) go to the frame unchanged.
 */
import { createContext, useContext } from "react";
import PlatformLayout from "./PlatformLayout";

const ProductFrameContext = createContext(null);

export function ProductFrameProvider({ frame, children }) {
  return (
    <ProductFrameContext.Provider value={frame || null}>
      {children}
    </ProductFrameContext.Provider>
  );
}

export default function ProductFrame({ children, ...props }) {
  const Frame = useContext(ProductFrameContext) || PlatformLayout;
  return <Frame {...props}>{children}</Frame>;
}
