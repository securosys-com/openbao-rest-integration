import Model from '@ember-data/model';
import { FormField, FormFieldGroups } from 'vault/vault/app-types';

export default class PkiTidyModel extends Model {
  version: string;
  acmeAccountSafetyBuffer: string;
  tidyAcme: boolean;
  enabled: boolean;
  intervalDuration: string;
  issuerSafetyBuffer: string;
  pauseDuration: string;
  safetyBuffer: string;
  tidyCertStore: boolean;
  tidyExpiredIssuers: boolean;
  tidyMoveLegacyCaBundle: boolean;
  tidyRevokedCertIssuerAssociations: boolean;
  tidyRevokedCerts: boolean;
  get useOpenAPI(): boolean;
  getHelpUrl(backend: string): string;
  allByKey: {
    intervalDuration: FormField[];
  };
  get allGroups(): FormFieldGroups[];
  get sharedFields(): FormFieldGroups[];
  get formFieldGroups(): FormFieldGroups[];
}
