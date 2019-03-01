/** ****************************************************************************************************
 * File: severityRating.js
 * Project: cvsscalculator
 * @author Nick Soggin <iSkore@users.noreply.github.com> on 18-Feb-2019
 *******************************************************************************************************/
'use strict';

const { severityRatings } = require( './variables' );

/**
 * severityRating
 *
 * Given a CVSS score, returns the name of the severity rating as defined in the CVSS standard.
 * The input needs to be a number between 0.0 to 10.0, to one decimal place of precision.
 *
 * The following error values may be returned instead of a severity rating name:
 *   NaN (JavaScript "Not a Number") - if the input is not a number.
 *   undefined - if the input is a number that is not within the range of any defined severity rating.
 *
 * @param {number} score - assessed score
 * @returns {*} - severity rating or undefined
 */
function severityRating( score ) {
	const
		severityRatingLength = severityRatings.length,
		validatedScore       = +score;
	
	if( isNaN( validatedScore ) ) {
		return validatedScore;
	}
	
	for( let i = 0; i < severityRatingLength; i++ ) {
		if( score >= severityRatings[ i ].bottom && score <= severityRatings[ i ].top ) {
			return severityRatings[ i ].name;
		}
	}
	
	return undefined;
}

module.exports = severityRating;
