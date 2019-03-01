/** ****************************************************************************************************
 * File: calculateCVSSFromMetrics.js
 * Project: cvsscalculator
 * @author Nick Soggin <iSkore@users.noreply.github.com> on 18-Feb-2019
 *******************************************************************************************************/
'use strict';

const
	roundUp1       = require( './roundUp1' ),
	severityRating = require( './severityRating' ),
	{
		CVSSVersionIdentifier,
		Weight,
		scopeCoefficient,
		exploitabilityCoefficient
	}              = require( './variables' );

/**
 * setDefaults
 *
 * Store the metric values and set defaults
 * Temporal and Environmental metrics are optional, so set them to "X" ("Not Defined") if no value was passed.
 *
 * @param {object} opts - options from calculateCVSSFromMetrics
 */
function setDefaults( opts ) {
	opts.AV = opts.AV || opts.AttackVector;
	opts.AC = opts.AC || opts.AttackComplexity;
	opts.PR = opts.PR || opts.PrivilegesRequired;
	opts.UI = opts.UI || opts.UserInteraction;
	opts.S  = opts.S || opts.Scope;
	opts.C  = opts.C || opts.Confidentiality;
	opts.I  = opts.I || opts.Integrity;
	opts.A  = opts.A || opts.Availability;
	
	opts.E  = opts.E || opts.ExploitCodeMaturity || 'X';
	opts.RL = opts.RL || opts.RemediationLevel || 'X';
	opts.RC = opts.RC || opts.ReportConfidence || 'X';
	
	opts.CR  = opts.CR || opts.ConfidentialityRequirement || 'X';
	opts.IR  = opts.IR || opts.IntegrityRequirement || 'X';
	opts.AR  = opts.AR || opts.AvailabilityRequirement || 'X';
	opts.MAV = opts.MAV || opts.ModifiedAttackVector || 'X';
	opts.MAC = opts.MAC || opts.ModifiedAttackComplexity || 'X';
	opts.MPR = opts.MPR || opts.ModifiedPrivilegesRequired || 'X';
	opts.MUI = opts.MUI || opts.ModifiedUserInteraction || 'X';
	opts.MS  = opts.MS || opts.ModifiedScope || 'X';
	opts.MC  = opts.MC || opts.ModifiedConfidentiality || 'X';
	opts.MI  = opts.MI || opts.ModifiedIntegrity || 'X';
	opts.MA  = opts.MA || opts.ModifiedAvailability || 'X';
}

/**
 * checkBaseOptions
 *
 * Ensure all base metrics are defined.
 * We need values for all Base Score metrics to calculate scores.
 * If any Base Score parameters are undefined, create an array of missing metrics and return it with an error.
 *
 * @param {object} opts - options from calculateCVSSFromMetrics
 * @returns {{success: boolean, errorType: string, errorMetrics: Array}|boolean}
 * object with error details if exist. false if no errors.
 */
function checkBaseOptions( opts ) {
	const badMetrics = [];
	
	typeof opts.AV === 'undefined' || opts.AV === '' ? badMetrics.push( 'AV' ) : void ( 0 );
	typeof opts.AC === 'undefined' || opts.AC === '' ? badMetrics.push( 'AC' ) : void ( 0 );
	typeof opts.PR === 'undefined' || opts.PR === '' ? badMetrics.push( 'PR' ) : void ( 0 );
	typeof opts.UI === 'undefined' || opts.UI === '' ? badMetrics.push( 'UI' ) : void ( 0 );
	typeof opts.S === 'undefined' || opts.S === '' ? badMetrics.push( 'S' ) : void ( 0 );
	typeof opts.C === 'undefined' || opts.C === '' ? badMetrics.push( 'C' ) : void ( 0 );
	typeof opts.I === 'undefined' || opts.I === '' ? badMetrics.push( 'I' ) : void ( 0 );
	typeof opts.A === 'undefined' || opts.A === '' ? badMetrics.push( 'A' ) : void ( 0 );
	
	return badMetrics.length > 0 ?
		{ success: false, errorType: 'MissingBaseMetric', errorMetrics: badMetrics } :
		false;
}

/**
 * checkMetricValues
 *
 * Check validity of metric values
 *
 * Use the Weight object to ensure that, for every metric, the metric value passed is valid.
 * If any invalid values are found, create an array of their metrics and return it with an error.
 *
 * The Privileges Required (PR) weight depends on Scope, but when checking the validity of PR we must not assume
 * that the given value for Scope is valid. We therefore always look at the weights for Unchanged Scope when
 * performing this check. The same applies for validation of Modified Privileges Required (MPR).
 *
 * The Weights object does not contain "X" ("Not Defined") values for Environmental metrics because we replace them
 * with their Base metric equivalents later in the function. For example, an MAV of "X" will be replaced with the
 * value given for AV. We therefore need to explicitly allow a value of "X" for Environmental metrics.
 *
 * @param {object} opts - options from calculateCVSSFromMetrics
 * @returns {{success: boolean, errorType: string, errorMetrics: Array}|boolean}
 * * object with error details if exist. false if no errors.
 */
function checkMetricValues( opts ) {
	const badMetrics = [];
	
	!Weight.AV.hasOwnProperty( opts.AV ) ? badMetrics.push( 'AV' ) : void ( 0 );
	!Weight.AC.hasOwnProperty( opts.AC ) ? badMetrics.push( 'AC' ) : void ( 0 );
	!Weight.PR.U.hasOwnProperty( opts.PR ) ? badMetrics.push( 'PR' ) : void ( 0 );
	!Weight.UI.hasOwnProperty( opts.UI ) ? badMetrics.push( 'UI' ) : void ( 0 );
	!Weight.S.hasOwnProperty( opts.S ) ? badMetrics.push( 'S' ) : void ( 0 );
	!Weight.CIA.hasOwnProperty( opts.C ) ? badMetrics.push( 'C' ) : void ( 0 );
	!Weight.CIA.hasOwnProperty( opts.I ) ? badMetrics.push( 'I' ) : void ( 0 );
	!Weight.CIA.hasOwnProperty( opts.A ) ? badMetrics.push( 'A' ) : void ( 0 );
	
	!Weight.E.hasOwnProperty( opts.E ) ? badMetrics.push( 'E' ) : void ( 0 );
	!Weight.RL.hasOwnProperty( opts.RL ) ? badMetrics.push( 'RL' ) : void ( 0 );
	!Weight.RC.hasOwnProperty( opts.RC ) ? badMetrics.push( 'RC' ) : void ( 0 );
	
	!( opts.CR === 'X' || Weight.CIAR.hasOwnProperty( opts.CR ) ) ? badMetrics.push( 'CR' ) : void ( 0 );
	!( opts.IR === 'X' || Weight.CIAR.hasOwnProperty( opts.IR ) ) ? badMetrics.push( 'IR' ) : void ( 0 );
	!( opts.AR === 'X' || Weight.CIAR.hasOwnProperty( opts.AR ) ) ? badMetrics.push( 'AR' ) : void ( 0 );
	!( opts.MAV === 'X' || Weight.AV.hasOwnProperty( opts.MAV ) ) ? badMetrics.push( 'MAV' ) : void ( 0 );
	!( opts.MAC === 'X' || Weight.AC.hasOwnProperty( opts.MAC ) ) ? badMetrics.push( 'MAC' ) : void ( 0 );
	!( opts.MPR === 'X' || Weight.PR.U.hasOwnProperty( opts.MPR ) ) ? badMetrics.push( 'MPR' ) : void ( 0 );
	!( opts.MUI === 'X' || Weight.UI.hasOwnProperty( opts.MUI ) ) ? badMetrics.push( 'MUI' ) : void ( 0 );
	!( opts.MS === 'X' || Weight.S.hasOwnProperty( opts.MS ) ) ? badMetrics.push( 'MS' ) : void ( 0 );
	!( opts.MC === 'X' || Weight.CIA.hasOwnProperty( opts.MC ) ) ? badMetrics.push( 'MC' ) : void ( 0 );
	!( opts.MI === 'X' || Weight.CIA.hasOwnProperty( opts.MI ) ) ? badMetrics.push( 'MI' ) : void ( 0 );
	!( opts.MA === 'X' || Weight.CIA.hasOwnProperty( opts.MA ) ) ? badMetrics.push( 'MA' ) : void ( 0 );
	
	return badMetrics.length > 0 ?
		{ success: false, errorType: 'UnknownMetricValue', errorMetrics: badMetrics } :
		false;
}

/**
 * gatherWeights
 *
 * Gather weights for all metrics
 *
 * @param {object} opts - options from calculateCVSSFromMetrics
 */
function gatherWeights( opts ) {
	opts.metricWeightAV = Weight.AV[ opts.AV ];
	opts.metricWeightAC = Weight.AC[ opts.AC ];
	
	// PR depends on the value of Scope (S).
	opts.metricWeightPR = Weight.PR[ opts.S ][ opts.PR ];
	opts.metricWeightUI = Weight.UI[ opts.UI ];
	opts.metricWeightS  = Weight.S[ opts.S ];
	opts.metricWeightC  = Weight.CIA[ opts.C ];
	opts.metricWeightI  = Weight.CIA[ opts.I ];
	opts.metricWeightA  = Weight.CIA[ opts.A ];
	
	opts.metricWeightE  = Weight.E[ opts.E ];
	opts.metricWeightRL = Weight.RL[ opts.RL ];
	opts.metricWeightRC = Weight.RC[ opts.RC ];
	
	// For metrics that are modified versions of Base Score metrics, e.g. Modified Attack Vector, use the value of
	// the Base Score metric if the modified version value is "X" ("Not Defined").
	opts.metricWeightCR  = Weight.CIAR[ opts.CR ];
	opts.metricWeightIR  = Weight.CIAR[ opts.IR ];
	opts.metricWeightAR  = Weight.CIAR[ opts.AR ];
	opts.metricWeightMAV = Weight.AV[ opts.MAV !== 'X' ? opts.MAV : opts.AV ];
	opts.metricWeightMAC = Weight.AC[ opts.MAC !== 'X' ? opts.MAC : opts.AC ];
	
	// Depends on MS.
	opts.metricWeightMPR = Weight.PR[ opts.MS !== 'X' ? opts.MS : opts.S ][ opts.MPR !== 'X' ? opts.MPR : opts.PR ];
	opts.metricWeightMUI = Weight.UI[ opts.MUI !== 'X' ? opts.MUI : opts.UI ];
	opts.metricWeightMS  = Weight.S[ opts.MS !== 'X' ? opts.MS : opts.S ];
	opts.metricWeightMC  = Weight.CIA[ opts.MC !== 'X' ? opts.MC : opts.C ];
	opts.metricWeightMI  = Weight.CIA[ opts.MI !== 'X' ? opts.MI : opts.I ];
	opts.metricWeightMA  = Weight.CIA[ opts.MA !== 'X' ? opts.MA : opts.A ];
}

function buildVectorString( opts ) {
	let vectorString = `${ CVSSVersionIdentifier }/AV:${ opts.AV }/AC:${ opts.AC }/PR:${ opts.PR }` +
		`/UI:${ opts.UI }/S:${ opts.S }/C:${ opts.C }/I:${ opts.I }/A:${ opts.A }`;
	
	opts.E !== 'X' ? vectorString += '/E:' + opts.E : void ( 0 );
	opts.RL !== 'X' ? vectorString += '/RL:' + opts.RL : void ( 0 );
	opts.RC !== 'X' ? vectorString += '/RC:' + opts.RC : void ( 0 );
	
	opts.CR !== 'X' ? vectorString += '/CR:' + opts.CR : void ( 0 );
	opts.IR !== 'X' ? vectorString += '/IR:' + opts.IR : void ( 0 );
	opts.AR !== 'X' ? vectorString += '/AR:' + opts.AR : void ( 0 );
	opts.MAV !== 'X' ? vectorString += '/MAV:' + opts.MAV : void ( 0 );
	opts.MAC !== 'X' ? vectorString += '/MAC:' + opts.MAC : void ( 0 );
	opts.MPR !== 'X' ? vectorString += '/MPR:' + opts.MPR : void ( 0 );
	opts.MUI !== 'X' ? vectorString += '/MUI:' + opts.MUI : void ( 0 );
	opts.MS !== 'X' ? vectorString += '/MS:' + opts.MS : void ( 0 );
	opts.MC !== 'X' ? vectorString += '/MC:' + opts.MC : void ( 0 );
	opts.MI !== 'X' ? vectorString += '/MI:' + opts.MI : void ( 0 );
	opts.MA !== 'X' ? vectorString += '/MA:' + opts.MA : void ( 0 );
	
	return vectorString;
}

/**
 * calculateCVSSFromMetrics
 *
 * Takes Base, Temporal and Environmental metric values as individual parameters. Their values are in the short format
 * defined in the CVSS v3.0 standard definition of the Vector String. For example, the AttackComplexity parameter
 * should be either "H" or "L".
 *
 * Returns Base, Temporal and Environmental scores, severity ratings, and an overall Vector String. All Base metrics
 * are required to generate this output. All Temporal and Environmental metric values are optional. Any that are not
 * passed default to "X" ("Not Defined").
 *
 * The output is an object which always has a property named "success".
 *
 * If no errors are encountered, success is Boolean "true", and the following other properties are defined containing
 * scores, severities and a vector string:
 *   baseMetricScore, baseSeverity,
 *   temporalMetricScore, temporalSeverity,
 *   environmentalMetricScore, environmentalSeverity,
 *   vectorString
 *
 * If errors are encountered, success is Boolean "false", and the following other properties are defined:
 *   errorType - a string indicating the error. Either:
 *                 "MissingBaseMetric", if at least one Base metric has not been defined; or
 *                 "UnknownMetricValue", if at least one metric value is invalid.
 *   errorMetrics - an array of strings representing the metrics at fault. The strings are abbreviated versions of the
 *                  metrics, as defined in the CVSS v3.0 standard definition of the Vector String.
 *
 * @param {object} opts - cvss options
 * @returns {{success: boolean, errorType: string, errorMetrics: Array}|boolean} - score or error
 */
function calculateCVSSFromMetrics( opts = {} ) {
	setDefaults( opts );
	
	let check;
	if( ( check = checkBaseOptions( opts ) ) ) {
		return check;
	} else if( ( check = checkMetricValues( opts ) ) ) {
		return check;
	}
	
	gatherWeights( opts );
	
	let
		baseScore,
		impactSubScore,
		exploitabalitySubScore   = exploitabilityCoefficient *
			opts.metricWeightAV *
			opts.metricWeightAC *
			opts.metricWeightPR *
			opts.metricWeightUI,
		impactSubScoreMultiplier = ( 1 - (
			( 1 - opts.metricWeightC ) *
			( 1 - opts.metricWeightI ) *
			( 1 - opts.metricWeightA )
		) );
	
	if( opts.S === 'U' ) {
		impactSubScore = opts.metricWeightS * impactSubScoreMultiplier;
	} else {
		impactSubScore = opts.metricWeightS * ( impactSubScoreMultiplier - 0.029 ) - 3.25 *
			Math.pow( impactSubScoreMultiplier - 0.02, 15 );
	}
	
	if( impactSubScore <= 0 ) {
		baseScore = 0;
	} else {
		if( opts.S === 'U' ) {
			baseScore = roundUp1( Math.min( ( exploitabalitySubScore + impactSubScore ), 10 ) );
		} else {
			baseScore = roundUp1( Math.min( ( exploitabalitySubScore + impactSubScore ) * scopeCoefficient, 10 ) );
		}
	}
	
	
	// CALCULATE THE CVSS TEMPORAL SCORE
	
	const
		temporalScore = roundUp1( baseScore * opts.metricWeightE * opts.metricWeightRL * opts.metricWeightRC );
	
	
	// CALCULATE THE CVSS ENVIRONMENTAL SCORE
	//
	// - envExploitabalitySubScore recalculates the Base Score Exploitability sub-score using any modified values from
	// the Environmental metrics group in place of the values specified in the Base Score, if any have been defined.
	// - envAdjustedImpactSubScore recalculates the Base Score Impact sub-score using any modified values from the
	//   Environmental metrics group in place of the values specified in the Base Score, and any additional weightings
	//   given in the Environmental metrics group.
	
	let
		envScore,
		envModifiedImpactSubScore,
		envModifiedExploitabalitySubScore = exploitabilityCoefficient *
			opts.metricWeightMAV *
			opts.metricWeightMAC *
			opts.metricWeightMPR *
			opts.metricWeightMUI;
	
	const
		envImpactSubScoreMultiplier = Math.min(
			1 - (
				( 1 - opts.metricWeightMC * opts.metricWeightCR ) *
				( 1 - opts.metricWeightMI * opts.metricWeightIR ) *
				( 1 - opts.metricWeightMA * opts.metricWeightAR )
			),
			0.915
		);
	
	if( opts.MS === 'U' ||
		( opts.MS === 'X' && opts.S === 'U' ) ) {
		envModifiedImpactSubScore = opts.metricWeightMS * envImpactSubScoreMultiplier;
		
		envScore = roundUp1(
			roundUp1(
				Math.min( ( envModifiedImpactSubScore + envModifiedExploitabalitySubScore ), 10 )
			) *
			opts.metricWeightE *
			opts.metricWeightRL *
			opts.metricWeightRC
		);
	} else {
		envModifiedImpactSubScore = opts.metricWeightMS *
			( envImpactSubScoreMultiplier - 0.029 ) - 3.25 *
			Math.pow( envImpactSubScoreMultiplier - 0.02, 15 );
		
		envScore = roundUp1(
			roundUp1(
				Math.min( scopeCoefficient * ( envModifiedImpactSubScore + envModifiedExploitabalitySubScore ), 10 )
			) *
			opts.metricWeightE *
			opts.metricWeightRL *
			opts.metricWeightRC
		);
	}
	
	if( envModifiedImpactSubScore <= 0 ) {
		envScore = 0;
	}
	
	// CONSTRUCT THE VECTOR STRING
	// Return an object containing the scores for all three metric groups, and an overall vector string.
	
	return {
		success: true,
		baseMetricScore: baseScore.toFixed( 1 ),
		baseSeverity: severityRating( +baseScore.toFixed( 1 ) ),
		
		temporalMetricScore: temporalScore.toFixed( 1 ),
		temporalSeverity: severityRating( +temporalScore.toFixed( 1 ) ),
		
		environmentalMetricScore: envScore.toFixed( 1 ),
		environmentalSeverity: severityRating( +envScore.toFixed( 1 ) ),
		
		vectorString: buildVectorString( opts )
	};
}

module.exports = calculateCVSSFromMetrics;
