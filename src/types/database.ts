export interface ColumnDefinition {
  field: string;
  type: string;
  null: string;
  key: string;
  default: string | null;
  extra: string;
}

export interface TableRelationship {
  constraintName: string;
  tableName: string;
  columnName: string;
  referencedTableName: string;
  referencedColumnName: string;
}

export interface TableOverview {
  name: string;
  rowCount: number;
  dataSizeKb: number;
  indexSizeKb: number;
  engine: string;
  collation: string;
}

export interface DatabaseOverview {
  database: string;
  totalTables: number;
  tables: TableOverview[];
}

export interface QueryResult<T = Record<string, unknown>> {
  rows: T[];
  rowCount: number;
  truncated: boolean;
  fields: Array<{
    name: string;
    type?: number;
  }>;
  executionDurationMs: number;
}
