/** ****************************************************************************************************
 * File: index.test.js
 * Project: cvsscalculator
 * @author Nick Soggin <iSkore@users.noreply.github.com> on 18-Feb-2019
 *******************************************************************************************************/
'use strict';

const
	chai   = require( 'chai' ),
	expect = chai.expect;

const
	CVSSCalculator           = require( '../CVSSCalculator' ),
	calculateCVSSFromMetrics = require( '../calculateCVSSFromMetrics' );

describe( '[CVSSCalculator]', () => {
	it( 'should calculate calculateCVSSFromMetrics', () => {
		const result = calculateCVSSFromMetrics( {
			AV: 'A', AC: 'H', PR: 'H', UI: 'R',
			S: 'U', C: 'N', I: 'N', A: 'L'
		} );
		
		expect( result ).to.deep.eq( {
			success: true,
			baseMetricScore: '1.8',
			baseSeverity: 'Low',
			temporalMetricScore: '1.8',
			temporalSeverity: 'Low',
			environmentalMetricScore: '1.8',
			environmentalSeverity: 'Low',
			vectorString: 'CVSS:3.0/AV:A/AC:H/PR:H/UI:R/S:U/C:N/I:N/A:L'
		} );
	} );
} );
