import { PartialType } from "@nestjs/mapped-types";
import { SignupUserDto } from "./signup-user.dto";

export class UpdateUserDto extends PartialType(SignupUserDto) {}