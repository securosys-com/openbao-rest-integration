/**
 * Copyright (c) HashiCorp, Inc.
 * SPDX-License-Identifier: MPL-2.0
 */
import { SELECTORS as TIDY_FORM } from './pki-tidy-form';

export const SELECTORS = {
  hdsAlertTitle: '[data-test-hds-alert-title]',
  hdsAlertDescription: '[data-test-hds-alert-description]',
  alertUpdatedAt: '[data-test-hds-alert-updated-at]',
  cancelTidyAction: '[data-test-cancel-tidy-action]',
  hdsAlertButtonText: '[data-test-cancel-tidy-action] .hds-button__text',
  timeStartedRow: '[data-test-value-div="Time started"]',
  timeFinishedRow: '[data-test-value-div="Time finished"]',
  cancelTidyModalBackground: '[data-test-modal-background="Cancel tidy?"]',
  tidyEmptyStateConfigure: '[data-test-tidy-empty-state-configure]',
  manualTidyToolbar: '[data-test-pki-manual-tidy-config]',
  autoTidyToolbar: '[data-test-pki-auto-tidy-config]',
  tidyConfigureModal: {
    configureTidyModal: '[data-test-modal-background="Tidy this mount"]',
    tidyModalAutoButton: '[data-test-tidy-modal-auto-button]',
    tidyModalManualButton: '[data-test-tidy-modal-manual-button]',
    tidyModalCancelButton: '[data-test-tidy-modal-cancel-button]',
    tidyOptionsModal: '[data-test-pki-tidy-options-modal]',
  },
  tidyEmptyState: '[data-test-component="empty-state"]',
  tidyForm: {
    ...TIDY_FORM,
  },
};
