'use strict';

const express = require('express');
const router = express.Router();
const { getReport, getDashboard, getReportJob, downloadReportJob } = require('../controllers/reportController');
const { resolveSchool } = require('../middleware/schoolContext');
const { requireSchoolAuth } = require('../middleware/auth');
const { validate } = require('../middleware/validate');
const { reportQuerySchema } = require('../middleware/schemas/reportSchemas');

// All report endpoints expose full financial data and CSV/accounting exports.
// Gate every route behind the finance permission (fix #887).
const requireFinanceRole = requireSchoolAuth(['owner', 'finance']);

router.use(resolveSchool);

/**
 * @swagger
 * /api/reports/dashboard:
 *   get:
 *     summary: Get payment dashboard metrics
 *     operationId: getDashboard
 *     tags:
 *       - Reports
 *     security:
 *       - BearerAuth: []
 *     responses:
 *       200:
 *         description: Dashboard metrics
 *       401:
 *         description: Unauthorized
 *       403:
 *         description: Forbidden — finance role required
 */

/**
 * @swagger
 * /api/reports:
 *   get:
 *     summary: Generate a payment report (synchronous for short ranges, async for >30 days)
 *     operationId: getReport
 *     tags:
 *       - Reports
 *     security:
 *       - BearerAuth: []
 *     parameters:
 *       - in: query
 *         name: startDate
 *         schema:
 *           type: string
 *           format: date
 *       - in: query
 *         name: endDate
 *         schema:
 *           type: string
 *           format: date
 *       - in: query
 *         name: format
 *         schema:
 *           type: string
 *           enum: [json, csv]
 *           default: json
 *     responses:
 *       200:
 *         description: Report data or async job reference
 *       400:
 *         description: Invalid date range
 *       401:
 *         description: Unauthorized
 *       403:
 *         description: Forbidden
 */

/**
 * @swagger
 * /api/reports/jobs/{jobId}:
 *   get:
 *     summary: Check status of an async report job
 *     operationId: getReportJob
 *     tags:
 *       - Reports
 *     security:
 *       - BearerAuth: []
 *     parameters:
 *       - in: path
 *         name: jobId
 *         required: true
 *         schema:
 *           type: string
 *     responses:
 *       200:
 *         description: Report job status
 *       401:
 *         description: Unauthorized
 *       404:
 *         description: Job not found
 */

/**
 * @swagger
 * /api/reports/jobs/{jobId}/download:
 *   get:
 *     summary: Download completed async report
 *     operationId: downloadReportJob
 *     tags:
 *       - Reports
 *     security:
 *       - BearerAuth: []
 *     parameters:
 *       - in: path
 *         name: jobId
 *         required: true
 *         schema:
 *           type: string
 *     responses:
 *       200:
 *         description: Report file (CSV or JSON)
 *       401:
 *         description: Unauthorized
 *       404:
 *         description: Job not found or not complete
 */
router.get('/jobs/:jobId', requireFinanceRole, validate(reportQuerySchema, 'query'), getReportJob);
router.get('/jobs/:jobId/download', requireFinanceRole, validate(reportQuerySchema, 'query'), downloadReportJob);
router.get('/', requireFinanceRole, validate(reportQuerySchema, 'query'), getReport);

module.exports = router;
