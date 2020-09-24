import faker from 'faker';
import 'cypress-wait-until';

context("Install", () => {
    beforeEach(() => { });

    afterEach(() => { });

    it("Setup Umbraco", () => {
        const username = Cypress.env('username');
        const password = Cypress.env('password');
        const connectionString = Cypress.env('connectionString');

        // Need a new release of umbraco-cypress-testhelpers to be able to use just this
        //cy.umbracoInstall(username, password, connectionString);

        // Hack: Everything below can be deleted after a new release of umbraco-cypress-testhelpers
        cy.visit(`/install`, { failOnStatusCode: false }).then(() => {
            cy.server();
            cy.route('GET', '/install/api/GetSetup').as('getSetup');
            cy.route('POST', '/install/api/PostValidateDatabaseConnection').as('validateDatabase');
            cy.route('GET', '/install/api/GetPackages').as('getPackages');
            cy.wait('@getSetup').then(() => {
                cy.get('input[placeholder="Full name"').type(faker.random.word());
                cy.get('input[placeholder="you@example.com"').type(username);
                cy.get('input[name="installer.current.model.password"').type(password);
                cy.get('.control-customize').click();
                cy.get('.controls button.btn').click();

                cy.get('#dbType').select('Custom connection string');
                cy.get('.input-block-level').type(connectionString);
                cy.get('form').submit();
                cy.wait('@validateDatabase').then(() => {
                    cy.get('.btn-link-reverse').click();
                    cy.waitUntil(() => cy.getCookie('UMB-XSRF-TOKEN'), { timeout: 2400000, interval: 500 }).then((p) => {
                        cy.log('Umbraco installed');
                    });
                });
            });
        });
    });
});