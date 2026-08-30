export type PasswordCheck = {
  id: string;
  label: string;
  test: (value: string) => boolean;
};

export const PASSWORD_CHECKS: PasswordCheck[] = [
  { id: "len", label: "At least 8 characters", test: (v) => v.length >= 8 },
  { id: "upper", label: "One uppercase letter (A–Z)", test: (v) => /[A-Z]/.test(v) },
  { id: "lower", label: "One lowercase letter (a–z)", test: (v) => /[a-z]/.test(v) },
  { id: "digit", label: "One number (0–9)", test: (v) => /\d/.test(v) },
  { id: "special", label: "One special character (!@#$%^&* …)", test: (v) => /[^A-Za-z0-9]/.test(v) },
];

export function passwordMeetsPolicy(value: string): boolean {
  return PASSWORD_CHECKS.every((c) => c.test(value));
}
