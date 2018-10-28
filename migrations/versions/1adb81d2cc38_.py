"""empty message

Revision ID: 1adb81d2cc38
Revises: 
Create Date: 2018-10-06 20:11:54.247791

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = '1adb81d2cc38'
down_revision = None
branch_labels = None
depends_on = None


def upgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.add_column('blacklistedTokens', sa.Column('token_id', sa.String(length=60), nullable=False, default=" "))
    op.create_unique_constraint(None, 'blacklistedTokens', ['token_id'])
    op.drop_column('blacklistedTokens', 'token')
    op.add_column('users', sa.Column('token_id', sa.String(length=60), nullable=True))
    op.alter_column('users', 'password_hash',
               existing_type=sa.VARCHAR(length=100),
               nullable=False)
    op.create_unique_constraint(None, 'users', ['token_id'])
    # ### end Alembic commands ###


def downgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.drop_constraint(None, 'users', type_='unique')
    op.alter_column('users', 'password_hash',
               existing_type=sa.VARCHAR(length=100),
               nullable=True)
    op.drop_column('users', 'token_id')
    op.add_column('blacklistedTokens', sa.Column('token', sa.VARCHAR(length=500), nullable=False))
    op.drop_constraint(None, 'blacklistedTokens', type_='unique')
    op.drop_column('blacklistedTokens', 'token_id')
    # ### end Alembic commands ###
