import { Injectable, Logger, OnModuleInit } from '@nestjs/common';
import { RpcException } from '@nestjs/microservices';
import * as bycrypt from 'bcrypt';
import { PrismaClient } from '@prisma/client';
import { LoginUserDto, RegisterUserDto } from './dto';

@Injectable()
export class AuthService extends PrismaClient implements OnModuleInit {
  private readonly logger = new Logger('AuthService');

  onModuleInit() {
    this.$connect();
    this.logger.log('MongoDB connected');
  }

  async registerUser(registerUserDto: RegisterUserDto) {
    const { name, email, password } = registerUserDto;
    try {
      const user = await this.user.findUnique({
        where: {
          email,
        },
      });
      if (user) {
        throw new RpcException({
          status: 409,
          message: 'User already exists',
        });
      }
      const newUser = await this.user.create({
        data: {
          name: name,
          email: email,
          password: bycrypt.hashSync(password, 10),
        },
      });
      return {
        user: {
          id: newUser.id,
          email: newUser.email,
          name: newUser.name,
        },
        token: 'xx1',
      };
    } catch (error) {
      throw new RpcException({
        status: 400,
        message: error.message,
      });
    }
  }
  async loginUser(loginUserDto: LoginUserDto) {
    const { email, password } = loginUserDto;
    try {
      const user = await this.user.findUnique({
        where: {
          email,
        },
      });
      if (!user) {
        throw new RpcException({
          status: 409,
          message: 'not valid user or password',
        });
      }
      const isPasswordValid = bycrypt.compareSync(password, user.password);
      if (!isPasswordValid) {
        throw new RpcException({
          status: 409,
          message: 'Valid your user or password',
        });
      }
      return {
        user: {
          id: user.id,
          email: user.email,
          name: user.name,
        },
        token: 'xx1',
      };
    } catch (error) {
      throw new RpcException({
        status: 400,
        message: error.message,
      });
    }
  }
}
