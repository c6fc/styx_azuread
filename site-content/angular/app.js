angular
    .module('app', ["ngRoute"])
    .config(['$routeProvider', '$locationProvider', function($routeProvider, $locationProvider) {

    	$locationProvider.hashPrefix('');

	   	$routeProvider
	   	.when('/', {
	   		templateUrl: "views/landing.html"
	   	})
	   	.when('/saml', {
	   		templateUrl: "views/dashboard.html",
	   		controller: "dashboardCtrl"
	   	})
	   	.otherwise({
	   		redirectTo: "/",
	   	});
    }])
    .directive('sidebar', function () {
    	return {
    		templateUrl: "sidebar.html"
    	};
    })
    ;

/*
var routeRequireLogon = function() {
	// console.log("Am logged in?: " + isLoggedOn());

	return new Promise((success, failure) => {
		if (!cognitoProvider.isLoggedOn()) {
			console.log('routeRequireLogon::isLoggedOn -> true');
			return success('/');
		}

		return success()
	);
};
*/