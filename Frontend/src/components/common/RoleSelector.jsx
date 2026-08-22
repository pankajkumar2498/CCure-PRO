export default function RoleSelector({
  roles = [],
  value = "",
  onChange,
  disabled = false,
  label = "Role",
}) {
  return (
    <div className="field">
      <label className="field-label">{label}</label>
      <div className="role-selector-row">
        <select
          className="field-input"
          value={value ?? ""}
          onChange={(event) =>
            onChange(event.target.value ? Number(event.target.value) : "")
          }
          disabled={disabled}
        >
          <option value="">Select role</option>
          {roles.map((role) => (
            <option key={role.id} value={role.id}>
              {role.name}
            </option>
          ))}
        </select>
      </div>
    </div>
  );
}
