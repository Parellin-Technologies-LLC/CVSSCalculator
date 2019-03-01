/** ****************************************************************************************************
 * File: variables.js
 * Project: cvsscalculator
 * @author Nick Soggin <iSkore@users.noreply.github.com> on 18-Feb-2019
 *******************************************************************************************************/
'use strict';

const
	CVSSVersionIdentifier     = 'CVSS:3.0',
	exploitabilityCoefficient = 8.22,
	scopeCoefficient          = 1.08;

/**
 * vectorStringRegex_30
 * A regular expression to validate that a CVSS 3.0 vector string is well formed. It checks metrics and metric
 * values. It does not check that a metric is specified more than once and it does not check that all base
 * metrics are present. These checks need to be performed separately.
 * @type {RegExp}
 */
const
	vectorStringRegex_30 = new RegExp(
		'^CVSS:3\.0\/((AV:[NALP]|AC:[LH]|PR:[UNLH]|UI:[NR]|S:[UC]|[CIA]:[NLH]|E:[XUPFH]|RL:[XOTWU]|RC:[XURC]|' +
		'[CIA]R:[XLMH]|MAV:[XNALP]|MAC:[XLH]|MPR:[XUNLH]|MUI:[XNR]|MS:[XUC]|M[CIA]:[XNLH])\/)*(AV:[NALP]|AC:[LH]|' +
		'PR:[UNLH]|UI:[NR]|S:[UC]|[CIA]:[NLH]|E:[XUPFH]|RL:[XOTWU]|RC:[XURC]|[CIA]R:[XLMH]|MAV:[XNALP]|MAC:[XLH]|' +
		'MPR:[XUNLH]|MUI:[XNR]|MS:[XUC]|M[CIA]:[XNLH])$'
	);


/**
 * Weight
 * Associative arrays mapping each metric value to the constant defined in the CVSS scoring formula in the CVSS v3.0
 * specification.
 * @type {
 * 	{
 * 		RC: {
 * 			R: number,
 * 			C: number,
 * 			U: number,
 * 			X: number
 * 		},
 * 		AC: {
 * 			H: number,
 * 			L: number
 * 		},
 * 		PR: {
 * 			C: {
 * 				H: number,
 * 				L: number,
 * 				N: number
 * 			},
 * 			U: {
 * 				H: number,
 * 				L: number,
 * 				N: number
 * 			}
 * 		},
 * 		S: {
 * 			C: number,
 * 			U: number
 * 		},
 * 		UI: {
 * 			R: number,
 * 			N: number
 * 		},
 * 		AV: {
 * 			P: number,
 * 			A: number,
 * 			L: number,
 * 			N: number
 * 		},
 * 		E: {
 * 			P: number,
 * 			U: number,
 * 			F: number,
 * 			X: number,
 * 			H: number
 * 		},
 * 		CIAR: {
 * 			X: number,
 * 			H: number,
 * 			L: number,
 * 			M: number
 * 		},
 * 		CIA: {
 * 			H: number,
 * 			L: number,
 * 			N: number
 * 		},
 * 		RL: {
 * 			T: number,
 * 			U: number,
 * 			W: number,
 * 			X: number,
 * 			O: number
 * 		}
 * 	}
 * }
 */
const
	Weight = {
		AV: { N: 0.85, A: 0.62, L: 0.55, P: 0.2 },
		AC: { H: 0.44, L: 0.77 },
		PR: {
			U: { N: 0.85, L: 0.62, H: 0.27 },
			C: { N: 0.85, L: 0.68, H: 0.5 }
		},
		UI: { N: 0.85, R: 0.62 },
		S: { U: 6.42, C: 7.52 },
		CIA: { N: 0, L: 0.22, H: 0.56 },
		E: { X: 1, U: 0.91, P: 0.94, F: 0.97, H: 1 },
		RL: { X: 1, O: 0.95, T: 0.96, W: 0.97, U: 1 },
		RC: { X: 1, U: 0.92, R: 0.96, C: 1 },
		CIAR: { X: 1, L: 0.5, M: 1, H: 1.5 }
	};

/**
 * severityRatings
 * Severity rating bands, as defined in the CVSS v3.0 specification.
 * @type {*[]}
 */
const
	severityRatings = [
		{ name: 'None', bottom: 0.0, top: 0.0 },
		{ name: 'Low', bottom: 0.1, top: 3.9 },
		{ name: 'Medium', bottom: 4.0, top: 6.9 },
		{ name: 'High', bottom: 7.0, top: 8.9 },
		{ name: 'Critical', bottom: 9.0, top: 10.0 }
	];

module.exports = {
	CVSSVersionIdentifier,
	exploitabilityCoefficient,
	scopeCoefficient,
	vectorStringRegex_30,
	Weight,
	severityRatings
};
