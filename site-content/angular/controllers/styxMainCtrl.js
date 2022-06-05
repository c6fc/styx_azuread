angular
   .module('app')
   .controller('styxMainCtrl', ['$scope', '$location', function($scope, $location) {
      console.log("StyxMCtrl v0.0.1 loaded");

      // ShowNav:
      const hiddenNavPagePatterns = [
        /^\/$/,
        /^\/forgot/,
      ];

      $scope.showNav = true;
      hiddenNavPagePatterns.forEach(function(e) {
        if (e.test($location.url())) {
          $scope.showNav = false;
          return false;
        }
      });
   }])
   .controller('dashboardCtrl', ['$timeout', '$scope', '$route', '$location', '$window', function($timeout, $scope, $route, $location, $window) {
      console.log("StyxDashboardCtrl v0.0.1 loaded");

      $scope.selectedEntitlement = {};
      $scope.saml_key = document.cookie?.split('key=')?.[1]?.split(';')?.[0];

      if (!!!$scope.saml_key) {
        $scope.$parent.showNav = false;
        location.href = "/"
        return false;
      }

      $scope.roles = [];
      $scope.getRoles = () => {
        $.get('/roles', (data) => {
          console.log(data);

          $scope.email = data.email;
          $scope.$parent.gravatar = md5(data.email);
          $scope.$parent.email = data.email;

          $scope.roles = data.role_entitlements.map(e => {
            const [idp, role] = e.split(',');
            const account = role.split(':')[4];
            const roleName = role.split("/")[1];

            return { idp, role, account, roleName };
          });

          //$timeout(() => false, 0);
          $scope.$digest();
          $scope.$parent.$digest();
        })
      };

      $scope.getRoles();

      $scope.getCreds = (index, entitlement) => {
        $scope.credentials = false;
        $scope.selectedEntitlement = entitlement;

        $('#credentialsModal').modal('show');

        $.get(`/sts?index=${index}`, (credentials) => {
          $scope.credentials = { success: true, msg: "Succeeded" };
          Object.assign($scope.credentials, credentials);

          $scope.$digest();
        });
      };

      $scope.doConsoleLogin = async (index, entitlement) => {
        $scope.roles = [];

        $.get(`/console?index=${index}`, (token) => {

          location.href = `https://signin.aws.amazon.com/federation`
          + `?Action=login`
          + `&Issuer=${encodeURIComponent(location.origin)}`
          + `&Destination=${encodeURIComponent('https://console.aws.amazon.com/')}`
          + `&SigninToken=${token.SigninToken}`;
        });
      };
   }])
  ;