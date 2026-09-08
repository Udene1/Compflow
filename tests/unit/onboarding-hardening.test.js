            await pool.query('INSERT INTO organization_frameworks (id, org_id, framework_id, status) VALUES ($1, $2, $3, $4);', ['fw_obj_99', emptyOrgId, 'soc2', 'selected']);
            const resNoConn = await invokeOnboarding({ method: 'POST', url: '/complete', sessionToken: emptySession.token });
            expect(resNoConn.statusCode).toBe(400); expect(resNoConn.body.error).toBe('Prerequisite Failed'); expect(resNoConn.body.message).toContain('verified cloud connection');
        });
    });

    describe('4. Authoritative Summary & Central Truthful Metrics', () => {
        it('returns zero findings and resources when scan is queued/pending (no invented numbers)', async () => {
            const summaryRes = await invokeOnboarding({ method: 'GET', url: '/summary', sessionToken: session.token });
            expect(summaryRes.statusCode).toBe(200); expect(summaryRes.body.scan.resourcesDiscovered).toBe(0); expect(summaryRes.body.compliance.evidenceCollected).toBe(0); expect(summaryRes.body.compliance.findings).toEqual({ critical: 0, high: 0, medium: 0, low: 0 });
        });
        it('enforces truthful phrasing via formatAssessmentSummary and assertTruthfulPhrasing', () => {
            const label = formatAssessmentSummary({ assessed: 87, total: 106, framework: 'soc2' });
            expect(label).toBe('87 of 106 selected SOC 2 controls assessed'); expect(label).not.toContain('% compliant');
            expect(() => assertTruthfulPhrasing('87 of 106 selected SOC 2 controls assessed')).not.toThrow(); expect(() => assertTruthfulPhrasing('82% SOC 2 compliant')).toThrow(/Deceptive compliance claim/); expect(() => assertTruthfulPhrasing('You are 91% compliant')).toThrow();
        });
        it('updates summary when actual scan results and findings are persisted in DB', async () => {
            const summaryOrgId = 'org_summary_hardening_101';
            const summaryUserId = 'usr_summary_hardening_101';
            await pool.query('INSERT INTO organizations (id, name) VALUES ($1, $2) ON CONFLICT (id) DO NOTHING;', [summaryOrgId, 'Summary Hardening Dedicated Corp']);
            await pool.query('INSERT INTO users (id, email, name) VALUES ($1, $2, $3) ON CONFLICT (id) DO NOTHING;', [summaryUserId, 'summary-hardening@lead.io', 'Summary Hardening Dedicated Corp Admin']);
            const summarySession = await createSessionToken({ id: summaryUserId, email: 'summary-hardening@lead.io' }, { id: summaryOrgId, name: 'Summary Hardening Dedicated Corp' }, ROLES.ADMIN, 1);
            await pool.query('INSERT INTO organization_frameworks (id, org_id, framework_id, status) VALUES ($1, $2, $3, $4) ON CONFLICT (id) DO NOTHING;', ['fw_summary_hardening_101', summaryOrgId, 'soc2', 'selected']);
            const connectionId = 'conn_summary_hardening_101';
            await pool.query('INSERT INTO cloud_connections (id, organization_id, provider, display_name, status) VALUES ($1, $2, $3, $4, $5) ON CONFLICT (id) DO NOTHING;', [connectionId, summaryOrgId, 'aws', 'Summary Hardening AWS', 'VERIFIED']);
            const scanId = 'scan_summary_hardening_101';
            await pool.query(`INSERT INTO scans (id, organization_id, connection_id, scan_type, status) VALUES ($1, $2, $3, 'initial_onboarding_scan', 'COMPLETED') ON CONFLICT (id) DO NOTHING;`, [scanId, summaryOrgId, connectionId]);
            await pool.query(`UPDATE scans SET resources_discovered = $1, findings_count = $2, evidence_count = $3 WHERE id = $4;`, [25, 4, 30, scanId]);
            await pool.query(`INSERT INTO findings (id, organization_id, scan_id, resource_id, control_id, severity, status, code) VALUES ($1, $2, $3, 's3-bucket-summary-1', 'S3_PUBLIC', 'CRITICAL', 'FAIL', 'S3_PUBLIC_ACCESS') ON CONFLICT (id) DO NOTHING;`, ['f_summary_hardening_critical', summaryOrgId, scanId]);
            await pool.query(`INSERT INTO findings (id, organization_id, scan_id, resource_id, control_id, severity, status, code) VALUES ($1, $2, $3, 'sg-summary-1', 'SG_OPEN_PORTS', 'HIGH', 'FAIL', 'SG_OPEN_SSH') ON CONFLICT (id) DO NOTHING;`, ['f_summary_hardening_high', summaryOrgId, scanId]);
            await pool.query(`INSERT INTO findings (id, organization_id, scan_id, resource_id, control_id, severity, status, code) VALUES ($1, $2, $3, 'rds-summary-1', 'RDS_PUBLIC', 'MEDIUM', 'FAIL', 'RDS_PUBLIC_IP') ON CONFLICT (id) DO NOTHING;`, ['f_summary_hardening_medium', summaryOrgId, scanId]);
            await pool.query(`INSERT INTO findings (id, organization_id, scan_id, resource_id, control_id, severity, status, code) VALUES ($1, $2, $3, 's3-bucket-summary-2', 'S3_PUBLIC', 'LOW', 'PASS', 'S3_BUCKET_ENCRYPTED') ON CONFLICT (id) DO NOTHING;`, ['f_summary_hardening_low', summaryOrgId, scanId]);
            const summaryRes = await invokeOnboarding({ method: 'GET', url: '/summary', sessionToken: summarySession.token });
            expect(summaryRes.statusCode).toBe(200); expect(summaryRes.body.scan.status).toBe('COMPLETED'); expect(summaryRes.body.scan.resourcesDiscovered).toBe(25); expect(summaryRes.body.compliance.evidenceCollected).toBe(30); expect(summaryRes.body.compliance.findings.critical).toBe(1); expect(summaryRes.body.compliance.findings.high).toBe(1); expect(summaryRes.body.compliance.findings.medium).toBe(1); expect(summaryRes.body.compliance.findings.low).toBe(1);
        });
    });

    describe('5. Authoritative Session Security & Cross-Instance Simulation', () => {