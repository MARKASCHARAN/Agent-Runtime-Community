import { IsString } from 'class-validator';

export class RegisterToolDto {
  @IsString()
  toolIdentity!: string;

  @IsString()
  publisher!: string;

  @IsString()
  schemaHash!: string;
}

export class VerifyToolDto {
  @IsString()
  toolIdentity!: string;

  @IsString()
  schemaHash!: string;
}
