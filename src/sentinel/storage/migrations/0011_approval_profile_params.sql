-- SPDX-License-Identifier: Apache-2.0
-- 0011_approval_profile_params.sql
--
-- The reviewer's P0.2 concern: `normalized_arguments_hash` was always ""
-- and never compared against the request. Fixing that requires binding
-- the profile params at issue time so the runner can verify a request
-- against them.
--
-- We store the operator-declared param dict as JSON (the hash covers
-- only those keys). Operators who don't pass --profile-param get an
-- empty dict (current behavior, no param binding). Operators who do
-- get strict pre-commitment: any run with different values for those
-- keys is refused at step 3d.

ALTER TABLE approvals
    ADD COLUMN profile_params_json TEXT NOT NULL DEFAULT '{}';
