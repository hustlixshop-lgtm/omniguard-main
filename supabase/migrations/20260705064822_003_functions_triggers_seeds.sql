/*
# OmniGuard Security Platform - Functions, Triggers, and Seed Data

1. Functions
- update_timestamp() - Auto-update timestamps on table updates
- handle_new_user() - Auto-create user profile when auth user is created
- is_org_member() - Check if user is member of organization
- is_org_admin() - Check if user has admin role in organization

2. Triggers
- Auto-update timestamps
- Auto-create user profile on auth signup
- Auto-create org membership when creating org

3. Seed Data
- Compliance frameworks (SOC2, ISO27001, HIPAA, PCI DSS, OWASP ASVS, NIST CSF)
- Built-in security policies
*/